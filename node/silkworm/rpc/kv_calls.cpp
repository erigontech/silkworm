/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "kv_calls.hpp"

#include <boost/date_time/posix_time/posix_time_io.hpp>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

types::VersionReply KvVersionCall::response_;

KvVersion higher_version(KvVersion lhs, KvVersion rhs) {
    uint32_t lhs_major = std::get<0>(lhs);
    uint32_t lhs_minor = std::get<1>(lhs);
    uint32_t rhs_major = std::get<0>(rhs);
    uint32_t rhs_minor = std::get<1>(rhs);
    if (rhs_major > lhs_major) {
        return rhs;
    }
    if (lhs_major > rhs_major) {
        return lhs;
    }
    if (rhs_minor > lhs_minor) {
        return rhs;
    }
    if (lhs_minor > rhs_minor) {
        return lhs;
    }
    return lhs;
}

void KvVersionCall::fill_predefined_reply() {
    const auto max_version = higher_version(kDbSchemaVersion, kKvApiVersion);
    KvVersionCall::response_.set_major(std::get<0>(max_version));
    KvVersionCall::response_.set_minor(std::get<1>(max_version));
    KvVersionCall::response_.set_patch(std::get<2>(max_version));
}

KvVersionCall::KvVersionCall(boost::asio::io_context& scheduler, remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::KV::AsyncService, google::protobuf::Empty, types::VersionReply>(scheduler, service, queue, handlers) {
}

void KvVersionCall::process(const google::protobuf::Empty* request) {
    SILK_TRACE << "KvVersionCall::process " << this << " request: " << request;

    const bool sent = send_response(response_);

    SILK_TRACE << "KvVersionCall::process " << this << " rsp: " << &response_ << " sent: " << sent;
}

KvVersionCallFactory::KvVersionCallFactory()
    : CallFactory<remote::KV::AsyncService, KvVersionCall>(&remote::KV::AsyncService::RequestVersion) {
    KvVersionCall::fill_predefined_reply();
}

mdbx::env* TxCall::chaindata_env_{nullptr};
boost::posix_time::milliseconds TxCall::max_ttl_duration_{kMaxTxDuration};
uint32_t TxCall::next_cursor_id_{0};

void TxCall::set_chaindata_env(mdbx::env* chaindata_env) {
    TxCall::chaindata_env_ = chaindata_env;
}

void TxCall::set_max_ttl_duration(const boost::posix_time::milliseconds& max_ttl_duration) {
    TxCall::max_ttl_duration_ = max_ttl_duration;
}

TxCall::TxCall(boost::asio::io_context& scheduler, remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : BidirectionalStreamingRpc<remote::KV::AsyncService, remote::Cursor, remote::Pair>(scheduler, service, queue, handlers),
    max_ttl_timer_{scheduler} {
}

void TxCall::start() {
    try {
        SILKWORM_ASSERT(!read_only_txn_);

        SILK_DEBUG << "TxCall::start MDBX info: " << chaindata_env_->get_info().mi_numreaders;

        // Create a new read-only transaction.
        read_only_txn_ = chaindata_env_->start_read();
        SILK_INFO << "Tx peer: " << peer() << " started tx: " << read_only_txn_.id();

        // Send an unsolicited message containing the transaction ID.
        remote::Pair kv_pair;
        kv_pair.set_txid(read_only_txn_.id());
        const bool sent = send_response(kv_pair);
        SILK_DEBUG << "TxCall::start message with txid=" << read_only_txn_.id() << " sent: " << sent;

        // Start a guard timer for closing and reopening to avoid long-lived transactions.
        max_ttl_timer_.expires_from_now(max_ttl_duration_);
        max_ttl_timer_.async_wait([&](const auto& ec) { handle_max_ttl_timer_expired(ec); });
        SILK_DEBUG << "Tx peer: " << peer() << " max TTL timer expires at: " << max_ttl_timer_.expires_at();
    } catch (const mdbx::exception& e) {
        const auto error_message = "start tx failed: " + std::string{e.what()};
        SILK_ERROR << "Tx peer: " << peer() << " " << error_message;
        close_with_error(grpc::Status{grpc::StatusCode::RESOURCE_EXHAUSTED, error_message});
    }
}

void TxCall::process(const remote::Cursor* request) {
    SILK_TRACE << "TxCall::process " << this << " request: " << request << " START";

    // Handle separately main use cases: cursor OPEN, cursor CLOSE and any other cursor operation.
    const auto cursor_op = request->op();
    if (cursor_op == remote::Op::OPEN) {
        handle_cursor_open(request);
    } else if (cursor_op == remote::Op::CLOSE) {
        handle_cursor_close(request);
    } else {
        handle_cursor_operation(request);
    }

    SILK_TRACE << "TxCall::process " << this << " request: " << request << " END";
}

void TxCall::end() {
    SILK_TRACE << "TxCall::end " << this << " START";

    // The client has closed its stream of requests, we can release cursors immediately.
    cursors_.clear();

    // Stop the max TTL timer.
    max_ttl_timer_.cancel();

    SILK_TRACE << "TxCall::end " << this << " END";
}

void TxCall::handle_cursor_open(const remote::Cursor* request) {
    const std::string& bucket_name = request->bucketname();

    // Bucket name must be a valid MDBX map name
    if (!db::has_map(read_only_txn_, bucket_name.c_str())) {
        const auto error_message = "unknown bucket: " + request->bucketname();
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        close_with_error(grpc::Status{grpc::StatusCode::INVALID_ARGUMENT, error_message});
        return;
    }

    // Create a new database cursor tracking also bucket name (needed for reopening).
    const db::MapConfig map_config{bucket_name.c_str()};
    db::Cursor cursor{read_only_txn_, map_config};
    const auto [cursor_it, inserted] = cursors_.insert({++next_cursor_id_, TxCursor{std::move(cursor), bucket_name}});

    // Send the assigned cursor ID back to the client.
    remote::Pair kv_pair;
    kv_pair.set_cursorid(cursor_it->first);
    SILK_INFO << "Tx peer: " << peer() << " opened cursor: " << kv_pair.cursorid();
    const bool sent = send_response(kv_pair);
    SILK_TRACE << "TxCall::handle_cursor_open " << this << " open cursor: " << kv_pair.cursorid() << " sent: " << sent;
}

void TxCall::handle_cursor_operation(const remote::Cursor* request) {
    const auto cursor_it = cursors_.find(request->cursor());
    if (cursor_it == cursors_.end()) {
        const auto error_message = "unknown cursor: " + std::to_string(request->cursor());
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        close_with_error(grpc::Status{grpc::StatusCode::INVALID_ARGUMENT, error_message});
        return;
    }
    db::Cursor& cursor = cursor_it->second.cursor;
    handle_operation(request, cursor);
    SILK_TRACE << "TxCall::handle_cursor_operation " << this << " cursor: " << request->cursor();
}

void TxCall::handle_cursor_close(const remote::Cursor* request) {
    const auto cursor_it = cursors_.find(request->cursor());
    if (cursor_it == cursors_.end()) {
        const auto error_message = "unknown cursor: " + std::to_string(request->cursor());
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        close_with_error(grpc::Status{grpc::StatusCode::INVALID_ARGUMENT, error_message});
        return;
    }
    cursors_.erase(cursor_it);
    SILK_INFO << "Tx peer: " << peer() << " closed cursor: " << request->cursor();
    const bool sent = send_response(remote::Pair{});
    SILK_TRACE << "TxCall::handle_cursor_close " << this << " close cursor: " << request->cursor() << " sent: " << sent;
}

void TxCall::handle_operation(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_INFO << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " cursor=" << request->cursor();

    switch (request->op()) {
        case remote::Op::FIRST: {
            handle_first(request, cursor);
        }
        break;
        case remote::Op::FIRST_DUP: {
            handle_first_dup(request, cursor);
        }
        break;
        case remote::Op::SEEK: {
            handle_seek(request, cursor);
        }
        break;
        case remote::Op::SEEK_BOTH: {
            handle_seek_both(request, cursor);
        }
        break;
        case remote::Op::SEEK_EXACT: {
            handle_seek_exact(request, cursor);
        }
        break;
        case remote::Op::SEEK_BOTH_EXACT: {
            handle_seek_both_exact(request, cursor);
        }
        break;
        case remote::Op::CURRENT: {
            handle_current(request, cursor);
        }
        break;
        case remote::Op::LAST: {
            handle_last(request, cursor);
        }
        break;
        case remote::Op::LAST_DUP: {
            handle_last_dup(request, cursor);
        }
        break;
        case remote::Op::NEXT: {
            handle_next(request, cursor);
        }
        break;
        case remote::Op::NEXT_DUP: {
            handle_next_dup(request, cursor);
        }
        break;
        case remote::Op::NEXT_NO_DUP: {
            handle_next_no_dup(request, cursor);
        }
        break;
        case remote::Op::PREV: {
            handle_prev(request, cursor);
        }
        break;
        default:
        //TODO(canepat) finish with error
        break;
    }

    SILK_TRACE << "TxCall::handle_operation " << this << " op=" << remote::Op_Name(request->op()) << " END";
}

void TxCall::handle_max_ttl_timer_expired(const boost::system::error_code& ec) {
    SILK_TRACE << "TxCall::handle_max_ttl_timer_expired " << this << " ec: " << ec << " START";
    if (!ec) {
        std::vector<CursorPosition> positions{cursors_.size()};
        const bool save_success = save_cursors(positions);
        if (!save_success) {
            finish_with_internal_error("cannot save state of cursors");
            return;
        }
        SILK_DEBUG << "Tx peer: " << peer() << " #cursors: " << cursors_.size() << " saved";

        read_only_txn_.abort();
        read_only_txn_ = chaindata_env_->start_read();

        const bool restore_success = restore_cursors(positions);
        if (!restore_success) {
            finish_with_internal_error("cannot restore state of cursors");
            return;
        }
        SILK_DEBUG << "Tx peer: " << peer() << " #cursors: " << cursors_.size() << " restored";

        max_ttl_timer_.expires_from_now(max_ttl_duration_);
        max_ttl_timer_.async_wait([&](const auto& error_code) { handle_max_ttl_timer_expired(error_code); });
        SILK_DEBUG << "Tx peer: " << peer() << " max TTL timer expires at: " << max_ttl_timer_.expires_at();
    }
    SILK_TRACE << "TxCall::handle_max_ttl_timer_expired " << this << " ec: " << ec << " END";
}

bool TxCall::save_cursors(std::vector<CursorPosition>& positions) {
    for (const auto& [_, tx_cursor]: cursors_) {
        const auto result = tx_cursor.cursor.current(/*throw_notfound=*/false);
        if (!result) {
            return false;
        }
        mdbx::slice key = result.key;
        mdbx::slice value = result.value;
        positions.emplace_back(CursorPosition{key.as_string(), value.as_string()});
    }

    return true;
}

bool TxCall::restore_cursors(std::vector<CursorPosition>& positions) {
    for (auto& [_, tx_cursor]: cursors_) {
        const db::MapConfig map_config{tx_cursor.bucket_name.c_str()};
        db::Cursor cursor{read_only_txn_, map_config};

        const auto& [key, value] = positions.back();
        positions.pop_back();
        mdbx::slice key_slice{key.c_str()};

        //TODO(canepat): change db::Cursor and replace with: cursor.map_flags() & MDBX_DUPSORT
        if (cursor.txn().get_handle_info(cursor.map()).flags & MDBX_DUPSORT) {
            mdbx::slice value_slice{value.c_str()};
            const auto lbm_result = cursor.lower_bound_multivalue(key_slice, value_slice, /*throw_notfound=*/false);
            if (!lbm_result) {
                return false;
            }
            // It may happen that key where we stopped disappeared after transaction reopen, then just move to next key
            if (!lbm_result.value) {
                const auto next_result = cursor.to_next(/*throw_notfound=*/false);
                if (!next_result) {
                    return false;
                }
            }
        } else {
            const bool found = cursor.seek(key_slice);
            if (!found) {
                return false;
            }
        }

        tx_cursor.cursor = std::move(cursor);
    }

    return true;
}

void TxCall::handle_first(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_first " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_first(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_first " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_first " << this << " END";
    }
}

void TxCall::handle_first_dup(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_first_dup " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_current_first_multi(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_first_dup " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_first_dup " << this << " END";
    }
}

void TxCall::handle_seek(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_seek " << this << " START";
    mdbx::slice key{request->k()};

    const mdbx::cursor::move_result result = (key.length() == 0) ?
        cursor.to_first(/*throw_notfound=*/false) :
        cursor.lower_bound(key, /*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_seek " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_seek " << this << " END";
    }
}

void TxCall::handle_seek_both(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_seek_both " << this << " START";
    mdbx::slice key{request->k()};
    mdbx::slice value{request->v()};

    const mdbx::cursor::move_result result = cursor.lower_bound_multivalue(key, value, /*throw_notfound=*/false);

    if (result) {
        remote::Pair kv_pair;
        kv_pair.set_v(result.value.as_string());
        const bool sent = send_response(kv_pair);
        SILK_TRACE << "TxCall::handle_seek_both " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_seek_both " << this << " END";
    }
}

void TxCall::handle_seek_exact(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_seek_exact " << this << " START";
    mdbx::slice key{request->k()};

    bool found = cursor.seek(key);

    if (found) {
        remote::Pair kv_pair;
        kv_pair.set_k(request->k());
        const bool sent = send_response(kv_pair);
        SILK_TRACE << "TxCall::handle_seek_exact " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_seek_exact " << this << " END";
    }
}

void TxCall::handle_seek_both_exact(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_seek_both_exact " << this << " START";
    mdbx::slice key{request->k()};
    mdbx::slice value{request->v()};

    const mdbx::cursor::move_result result = cursor.find_multivalue(key, value, /*throw_notfound=*/false);

    if (result) {
        remote::Pair kv_pair;
        kv_pair.set_k(request->k());
        kv_pair.set_v(result.value.as_string());
        const bool sent = send_response(kv_pair);
        SILK_TRACE << "TxCall::handle_seek_both_exact " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_seek_both_exact " << this << " END";
    }
}

void TxCall::handle_current(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_current " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_next_first_multi(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_current " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_current " << this << " END";
    }
}

void TxCall::handle_last(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_last " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_last(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_last " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_last " << this << " END";
    }
}

void TxCall::handle_last_dup(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_last_dup " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_current_last_multi(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_last_dup " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_last_dup " << this << " END";
    }
}

void TxCall::handle_next(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_next " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_next(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_next " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_next " << this << " END";
    }
}

void TxCall::handle_next_dup(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_next_dup " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_current_next_multi(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_next_dup " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_next_dup " << this << " END";
    }
}

void TxCall::handle_next_no_dup(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_next_no_dup " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_next_first_multi(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_next_no_dup " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_next_no_dup " << this << " END";
    }
}

void TxCall::handle_prev(const remote::Cursor* request, db::Cursor& cursor) {
    SILK_TRACE << "TxCall::handle_prev " << this << " START";

    const mdbx::cursor::move_result result = cursor.to_previous(/*throw_notfound=*/false);

    if (result) {
        const bool sent = send_response_pair(result);
        SILK_TRACE << "TxCall::handle_prev " << this << " sent: " << sent << " END";
    } else {
        finish_with_internal_error(request);
        SILK_TRACE << "TxCall::handle_prev " << this << " END";
    }
}

bool TxCall::send_response_pair(const mdbx::cursor::move_result& result) {
    remote::Pair kv_pair;
    kv_pair.set_k(result.key.as_string());
    kv_pair.set_v(result.value.as_string());
    return send_response(kv_pair);
}

void TxCall::finish_with_internal_error(const remote::Cursor* request) {
    finish_with_internal_error("cannot execute " + remote::Op_Name(request->op()) + " on cursor: " + std::to_string(request->cursor()));
}

void TxCall::finish_with_internal_error(const std::string& error_message) {
    SILK_ERROR << "Tx peer: " << peer() << " " << error_message;
    close_with_error(grpc::Status{grpc::StatusCode::INTERNAL, error_message});
}

TxCallFactory::TxCallFactory(const EthereumBackEnd& backend)
    : CallFactory<remote::KV::AsyncService, TxCall>(&remote::KV::AsyncService::RequestTx) {
    TxCall::set_chaindata_env(backend.chaindata_env());
}

StateChangesCall::StateChangesCall(boost::asio::io_context& scheduler, remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : ServerStreamingRpc<remote::KV::AsyncService, remote::StateChangeRequest, remote::StateChangeBatch>(scheduler, service, queue, handlers) {
}

void StateChangesCall::process(const remote::StateChangeRequest* request) {
    SILK_TRACE << "StateChangesCall::process " << this << " request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::StateChangeBatch response1;
    send_response(response1);
    remote::StateChangeBatch response2;
    send_response(response2);

    const bool closed = close();

    SILK_TRACE << "StateChangesCall::process " << this << " closed: " << closed;
}

StateChangesCallFactory::StateChangesCallFactory()
    : CallFactory<remote::KV::AsyncService, StateChangesCall>(&remote::KV::AsyncService::RequestStateChanges) {
}

KvService::KvService(const EthereumBackEnd& backend) : tx_factory_{backend} {
}

void KvService::register_kv_request_calls(boost::asio::io_context& scheduler, remote::KV::AsyncService* async_service, grpc::ServerCompletionQueue* queue) {
    // Register one requested call for each RPC factory
    kv_version_factory_.create_rpc(scheduler, async_service, queue);
    tx_factory_.create_rpc(scheduler, async_service, queue);
    state_changes_factory_.create_rpc(scheduler, async_service, queue);
}

} // namespace silkworm::rpc
