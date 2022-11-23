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

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <gsl/util>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

namespace detail {

    std::string dump_mdbx_result(const mdbx::cursor::move_result& result) {
        std::string dump{"done="};
        dump.append(std::to_string(result.done));
        dump.append(" bool(key)=");
        dump.append(std::to_string(bool(result.key)));
        dump.append(" bool(value)=");
        dump.append(std::to_string(bool(result.value)));
        return dump;
    }

}  // namespace detail

using boost::asio::awaitable;
using boost::asio::experimental::as_tuple;
using namespace boost::asio::experimental::awaitable_operators;
using boost::asio::steady_timer;
using boost::asio::use_awaitable;

KvVersion higher_version_ignoring_patch(KvVersion lhs, KvVersion rhs) {
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

types::VersionReply KvVersionCall::response_;

void KvVersionCall::fill_predefined_reply() {
    const auto max_version = higher_version_ignoring_patch(kDbSchemaVersion, kKvApiVersion);
    KvVersionCall::response_.set_major(std::get<0>(max_version));
    KvVersionCall::response_.set_minor(std::get<1>(max_version));
    KvVersionCall::response_.set_patch(std::get<2>(max_version));
}

awaitable<void> KvVersionCall::operator()() {
    SILK_TRACE << "KvVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "KvVersionCall END version: " << response_.major() << "." << response_.minor() << "." << response_.patch();
}

mdbx::env* TxCall::chaindata_env_{nullptr};
std::chrono::milliseconds TxCall::max_ttl_duration_{kMaxTxDuration};

void TxCall::set_chaindata_env(mdbx::env* chaindata_env) {
    TxCall::chaindata_env_ = chaindata_env;
}

void TxCall::set_max_ttl_duration(const std::chrono::milliseconds& max_ttl_duration) {
    TxCall::max_ttl_duration_ = max_ttl_duration;
}

awaitable<void> TxCall::operator()() {
    SILK_TRACE << "TxCall peer: " << peer() << " MDBX readers: " << chaindata_env_->get_info().mi_numreaders;

    grpc::Status status{grpc::Status::OK};
    try {
        // Create a new read-only transaction.
        read_only_txn_ = chaindata_env_->start_read();
        SILK_DEBUG << "TxCall peer: " << peer() << " started tx: " << read_only_txn_.id();

        // Send an unsolicited message containing the transaction ID.
        remote::Pair txid_pair;
        txid_pair.set_txid(read_only_txn_.id());
        if (!co_await agrpc::write(responder_, txid_pair)) {
            SILK_WARN << "Tx closed by peer: " << server_context_.peer() << " error: write failed";
            co_await agrpc::finish(responder_, grpc::Status::OK);
            co_return;
        }
        SILK_DEBUG << "TxCall announcement with txid=" << read_only_txn_.id() << " sent";

        // Create guard timers to 1) close idle transactions 2) close and reopen long-lived transactions.
        boost::asio::steady_timer max_idle_alarm{grpc_context_}, max_ttl_alarm{grpc_context_};
        max_idle_alarm.expires_after(max_idle_duration_);
        max_ttl_alarm.expires_after(max_ttl_duration_);

        // Initiate read and write streams
        agrpc::GrpcStream read_stream{grpc_context_}, write_stream{grpc_context_};
        const auto initiate_write = [&](const remote::Pair& response) {
            if (!write_stream.is_running()) {
                write_stream.initiate(agrpc::write, responder_, response);
            }
        };
        remote::Cursor request;
        read_stream.initiate(agrpc::read, responder_, request);

        boost::asio::cancellation_signal signal;
        bool completed{false};
        while (!completed) {
            const auto rv = co_await (
                read_stream.next() ||
                max_idle_alarm.async_wait(as_tuple(use_awaitable)) ||
                max_ttl_alarm.async_wait(as_tuple(use_awaitable)) ||
                write_stream.next());
            if (0 == rv.index()) {  // read request completed
                if (const bool read_ok = std::get<0>(rv); read_ok) {
                    // Handle incoming request from client
                    remote::Pair response{};
                    handle(&request, response);
                    // Schedule write for response
                    initiate_write(response);
                    // Reset request and schedule subsequent read
                    request.Clear();
                    read_stream.initiate(agrpc::read, responder_, request);
                    // Update idle timer deadline every time we receive an incoming request
                    max_idle_alarm.expires_after(max_idle_duration_);
                } else {
                    SILK_WARN << "Tx closed by peer: " << server_context_.peer() << " error: read failed";
                    completed = true;
                }
            } else if (1 == rv.index()) {  // max idle timeout expired
                if (const auto [max_idle_ec] = std::get<1>(rv); max_idle_ec != boost::asio::error::operation_aborted) {
                    const auto error_msg{"no incoming request in " + std::to_string(max_idle_duration_.count()) + " ms"};
                    SILK_WARN << "Tx idle peer: " << server_context_.peer() << " error: " << error_msg;
                    status = grpc::Status{grpc::StatusCode::DEADLINE_EXCEEDED, error_msg};
                } else {
                    status = grpc::Status::CANCELLED;
                }
                completed = true;
            } else if (2 == rv.index()) {  // max TTL timeout expired
                if (const auto [max_ttl_ec] = std::get<2>(rv); max_ttl_ec != boost::asio::error::operation_aborted) {
                    handle_max_ttl_timer_expired();
                    max_ttl_alarm.expires_after(max_ttl_duration_);
                } else {
                    status = grpc::Status::CANCELLED;
                    completed = true;
                }
            } else {  // write response completed
                if (const bool write_ok = std::get<3>(rv); !write_ok) {
                    SILK_WARN << "Tx closed by peer: " << server_context_.peer() << " error: write failed";
                    completed = true;
                }
            }
        }
        SILK_DEBUG << "TxCall peer: " << peer() << " read/write loop completed";
    } catch (const mdbx::exception& e) {
        const auto error_message = "start tx failed: " + std::string{e.what()};
        SILK_ERROR << "Tx peer: " << peer() << " " << error_message;
        status = grpc::Status{grpc::StatusCode::RESOURCE_EXHAUSTED, error_message};
    } catch (const server::CallException& ce) {
        status = ce.status();
    } catch (const std::exception& exc) {
        status = grpc::Status{grpc::StatusCode::INTERNAL, exc.what()};
    }

    co_await agrpc::finish(responder_, status);

    SILK_TRACE << "TxCall END peer: " << peer() << " status: " << status;
}

void TxCall::handle(const remote::Cursor* request, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle " << this << " request: " << request << " START";

    // Handle separately main use cases: cursor OPEN, cursor CLOSE and any other cursor operation.
    const auto cursor_op = request->op();
    if (cursor_op == remote::Op::OPEN) {
        handle_cursor_open(request, response);
    } else if (cursor_op == remote::Op::CLOSE) {
        handle_cursor_close(request);
    } else {
        handle_cursor_operation(request, response);
    }

    SILK_TRACE << "TxCall::handle " << this << " request: " << request << " END";
}

void TxCall::handle_cursor_open(const remote::Cursor* request, remote::Pair& response) {
    const std::string& bucket_name = request->bucketname();

    // Bucket name must be a valid MDBX map name
    if (!db::has_map(read_only_txn_, bucket_name.c_str())) {
        const auto err = "unknown bucket: " + request->bucketname();
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << err;
        throw_with_error(grpc::Status{grpc::StatusCode::INVALID_ARGUMENT, err});
    }

    // The number of opened cursors shall not exceed the maximum threshold.
    if (cursors_.size() == kMaxTxCursors) {
        const auto err = "maximum cursors per txn reached: " + std::to_string(cursors_.size());
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << err;
        throw_with_error(grpc::Status{grpc::StatusCode::RESOURCE_EXHAUSTED, err});
    }

    // Create a new database cursor tracking also bucket name (needed for reopening).
    const db::MapConfig map_config{bucket_name.c_str()};
    db::Cursor cursor{read_only_txn_, map_config};
    const auto [cursor_it, inserted] = cursors_.insert({++last_cursor_id_, TxCursor{std::move(cursor), bucket_name}});

    SILKWORM_ASSERT(cursor_it->first == last_cursor_id_);

    // The assigned cursor ID shall not be already in use (after cursor ID wrapping).
    if (!inserted) {
        const auto error_message = "assigned cursor ID already in use: " + std::to_string(last_cursor_id_);
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        throw_with_error(grpc::Status{grpc::StatusCode::ALREADY_EXISTS, error_message});
    }

    // Send the assigned cursor ID back to the client.
    response.set_cursorid(cursor_it->first);
    SILK_DEBUG << "Tx peer: " << peer() << " opened cursor: " << response.cursorid();
}

void TxCall::handle_cursor_operation(const remote::Cursor* request, remote::Pair& response) {
    const auto cursor_it = cursors_.find(request->cursor());
    if (cursor_it == cursors_.end()) {
        const auto error_message = "unknown cursor: " + std::to_string(request->cursor());
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        throw_with_error(grpc::Status{grpc::StatusCode::INVALID_ARGUMENT, error_message});
    }
    db::Cursor& cursor = cursor_it->second.cursor;
    try {
        handle_operation(request, cursor, response);
    } catch (const std::exception& exc) {
        throw_with_internal_error(request, exc);
    }
    SILK_TRACE << "TxCall::handle_cursor_operation " << this << " cursor: " << request->cursor();
}

void TxCall::handle_cursor_close(const remote::Cursor* request) {
    const auto cursor_it = cursors_.find(request->cursor());
    if (cursor_it == cursors_.end()) {
        const auto error_message = "unknown cursor: " + std::to_string(request->cursor());
        SILK_ERROR << "Tx peer: " << peer() << " op: " << remote::Op_Name(request->op()) << " " << error_message;
        throw_with_error(grpc::Status{grpc::StatusCode::INVALID_ARGUMENT, error_message});
    }
    cursors_.erase(cursor_it);
    SILK_DEBUG << "Tx peer: " << peer() << " closed cursor: " << request->cursor();
}

void TxCall::handle_operation(const remote::Cursor* request, db::Cursor& cursor, remote::Pair& response) {
    SILK_DEBUG << "Tx peer=" << peer() << " op=" << remote::Op_Name(request->op()) << " cursor=" << request->cursor();

    switch (request->op()) {
        case remote::Op::FIRST: {
            handle_first(cursor, response);
        } break;
        case remote::Op::FIRST_DUP: {
            handle_first_dup(cursor, response);
        } break;
        case remote::Op::SEEK: {
            handle_seek(request, cursor, response);
        } break;
        case remote::Op::SEEK_BOTH: {
            handle_seek_both(request, cursor, response);
        } break;
        case remote::Op::SEEK_EXACT: {
            handle_seek_exact(request, cursor, response);
        } break;
        case remote::Op::SEEK_BOTH_EXACT: {
            handle_seek_both_exact(request, cursor, response);
        } break;
        case remote::Op::CURRENT: {
            handle_current(cursor, response);
        } break;
        case remote::Op::LAST: {
            handle_last(cursor, response);
        } break;
        case remote::Op::LAST_DUP: {
            handle_last_dup(cursor, response);
        } break;
        case remote::Op::NEXT: {
            handle_next(cursor, response);
        } break;
        case remote::Op::NEXT_DUP: {
            handle_next_dup(cursor, response);
        } break;
        case remote::Op::NEXT_NO_DUP: {
            handle_next_no_dup(cursor, response);
        } break;
        case remote::Op::PREV: {
            handle_prev(cursor, response);
        } break;
        case remote::Op::PREV_DUP: {
            handle_prev_dup(cursor, response);
        } break;
        case remote::Op::PREV_NO_DUP: {
            handle_prev_no_dup(cursor, response);
        } break;
        default: {
            std::string error_message{"unhandled operation "};
            error_message.append(remote::Op_Name(request->op()));
            error_message.append(" on cursor: ");
            error_message.append(std::to_string(request->cursor()));
            throw_with_internal_error(error_message);
        } break;
    }

    SILK_TRACE << "TxCall::handle_operation " << this << " op=" << remote::Op_Name(request->op()) << " END";
}

void TxCall::handle_max_ttl_timer_expired() {
    // Save the whole state of the transaction (i.e. all cursor positions)
    std::vector<CursorPosition> positions;
    const bool save_success = save_cursors(positions);
    if (!save_success) {
        throw_with_internal_error("cannot save state of cursors");
    }
    SILK_DEBUG << "Tx peer: " << peer() << " #cursors: " << cursors_.size() << " saved";

    // Close and reopen to avoid long-lived transactions (resource-consuming for MDBX)
    read_only_txn_.abort();
    read_only_txn_ = chaindata_env_->start_read();

    // Restore the whole state of the transaction (i.e. all cursor positions)
    const bool restore_success = restore_cursors(positions);
    if (!restore_success) {
        throw_with_internal_error("cannot restore state of cursors");
    }
    SILK_DEBUG << "Tx peer: " << peer() << " #cursors: " << cursors_.size() << " restored";
}

bool TxCall::save_cursors(std::vector<CursorPosition>& positions) {
    for (const auto& [cursor_id, tx_cursor] : cursors_) {
        const auto result = tx_cursor.cursor.current(/*throw_notfound=*/false);
        SILK_DEBUG << "Tx save cursor: " << cursor_id << " result: " << detail::dump_mdbx_result(result);
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
    SILKWORM_ASSERT(positions.size() == cursors_.size());

    auto position_iterator = positions.begin();

    for (auto& [cursor_id, tx_cursor] : cursors_) {
        const std::string& bucket_name = tx_cursor.bucket_name;
        const db::MapConfig map_config{bucket_name.c_str()};

        // Bind each cursor to the renewed transaction.
        db::Cursor& cursor = tx_cursor.cursor;
        cursor.bind(read_only_txn_, map_config);

        const auto& [current_key, current_value] = *position_iterator;
        ++position_iterator;
        SILK_DEBUG << "Tx restore cursor " << cursor_id << " current_key: " << current_key << " current_value: " << current_value;
        mdbx::slice key{current_key.c_str()};

        // Restore each cursor saved position.
        // TODO(canepat): change db::Cursor and replace with: cursor.map_flags() & MDBX_DUPSORT
        if (cursor.txn().get_handle_info(cursor.map()).flags & MDBX_DUPSORT) {
            /* multi-value table */
            mdbx::slice value{current_value.c_str()};
            const auto lbm_result = cursor.lower_bound_multivalue(key, value, /*throw_notfound=*/false);
            SILK_DEBUG << "Tx restore cursor " << cursor_id << " for: " << bucket_name << " lbm_result: " << detail::dump_mdbx_result(lbm_result);
            // It may happen that key where we stopped disappeared after transaction reopen, then just move to next key
            if (!lbm_result) {
                const auto next_result = cursor.to_next(/*throw_notfound=*/false);
                SILK_DEBUG << "Tx restore cursor " << cursor_id << " for: " << bucket_name << " next_result: " << detail::dump_mdbx_result(next_result);
                if (!next_result) {
                    return false;
                }
            }
        } else {
            /* single-value table */
            const auto result = (key.length() == 0) ? cursor.to_first(/*throw_notfound=*/false) : cursor.lower_bound(key, /*throw_notfound=*/false);
            SILK_DEBUG << "Tx restore cursor " << cursor_id << " for: " << bucket_name << " result: " << detail::dump_mdbx_result(result);
            if (!result) {
                return false;
            }
        }
    }

    return true;
}

void TxCall::handle_first(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_first " << this << " START";

    const auto result = cursor.to_first(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx FIRST result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_first " << this << " END";
}

void TxCall::handle_first_dup(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_first_dup " << this << " START";

    const auto result = cursor.to_current_first_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx FIRST_DUP result: " << detail::dump_mdbx_result(result);

    // Do not use `operator bool(result)` to avoid MDBX Assertion `!done || (bool(key) && bool(value))' failed
    if (result.done && result.value) {
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_first_dup " << this << " END";
}

void TxCall::handle_seek(const remote::Cursor* request, db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_seek " << this << " START";
    mdbx::slice key{request->k()};

    const auto result = (key.length() == 0) ? cursor.to_first(/*throw_notfound=*/false) : cursor.lower_bound(key, /*throw_notfound=*/false);
    SILK_DEBUG << "Tx SEEK result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_seek " << this << " END";
}

void TxCall::handle_seek_both(const remote::Cursor* request, db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_seek_both " << this << " START";
    mdbx::slice key{request->k()};
    mdbx::slice value{request->v()};

    const auto result = cursor.lower_bound_multivalue(key, value, /*throw_notfound=*/false);
    SILK_DEBUG << "Tx SEEK_BOTH result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_seek_both " << this << " END";
}

void TxCall::handle_seek_exact(const remote::Cursor* request, db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_seek_exact " << this << " START";
    mdbx::slice key{request->k()};

    const bool found = cursor.seek(key);
    SILK_DEBUG << "Tx SEEK_EXACT found: " << std::boolalpha << found;

    if (found) {
        response.set_k(request->k());
    }

    SILK_TRACE << "TxCall::handle_seek_exact " << this << " END";
}

void TxCall::handle_seek_both_exact(const remote::Cursor* request, db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_seek_both_exact " << this << " START";
    mdbx::slice key{request->k()};
    mdbx::slice value{request->v()};

    const auto result = cursor.find_multivalue(key, value, /*throw_notfound=*/false);
    SILK_DEBUG << "Tx SEEK_BOTH_EXACT result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(request->k());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_seek_both_exact " << this << " END";
}

void TxCall::handle_current(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_current " << this << " START";

    const auto result = cursor.current(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx CURRENT result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_current " << this << " END";
}

void TxCall::handle_last(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_last " << this << " START";

    const auto result = cursor.to_last(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx LAST result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_last " << this << " END";
}

void TxCall::handle_last_dup(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_last_dup " << this << " START";

    const auto result = cursor.to_current_last_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx LAST_DUP result: " << detail::dump_mdbx_result(result);

    // Do not use `operator bool(result)` to avoid MDBX Assertion `!done || (bool(key) && bool(value))' failed
    if (result.done && result.value) {
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_last_dup " << this << " END";
}

void TxCall::handle_next(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_next " << this << " START";

    const auto result = cursor.to_next(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx NEXT result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_next " << this << " END";
}

void TxCall::handle_next_dup(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_next_dup " << this << " START";

    const auto result = cursor.to_current_next_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx NEXT_DUP result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_next_dup " << this << " END";
}

void TxCall::handle_next_no_dup(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_next_no_dup " << this << " START";

    const auto result = cursor.to_next_first_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx NEXT_NO_DUP result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_next_no_dup " << this << " END";
}

void TxCall::handle_prev(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_prev " << this << " START";

    const auto result = cursor.to_previous(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx PREV result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_prev " << this << " END";
}

void TxCall::handle_prev_dup(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_prev_dup " << this << " START";

    const auto result = cursor.to_current_prev_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx PREV_DUP result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_prev_dup " << this << " END";
}

void TxCall::handle_prev_no_dup(db::Cursor& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_prev_no_dup " << this << " START";

    const auto result = cursor.to_previous_last_multi(/*throw_notfound=*/false);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_prev_no_dup " << this << " END";
}

void TxCall::throw_with_internal_error(const remote::Cursor* request, const std::exception& exc) {
    std::string error_message{"exception: "};
    error_message.append(exc.what());
    error_message.append(" in ");
    error_message.append(remote::Op_Name(request->op()));
    error_message.append(" on cursor: ");
    error_message.append(std::to_string(request->cursor()));
    throw_with_error(grpc::Status{grpc::StatusCode::INTERNAL, error_message});
}

void TxCall::throw_with_internal_error(const std::string& message) {
    throw_with_error(grpc::Status{grpc::StatusCode::INTERNAL, message});
}

void TxCall::throw_with_error(grpc::Status&& status) {
    SILK_ERROR << "Tx peer: " << peer() << " " << status.error_message();
    throw server::CallException{std::move(status)};
}

StateChangeSource* StateChangesCall::source_{nullptr};

void StateChangesCall::set_source(StateChangeSource* source) {
    StateChangesCall::source_ = source;
}

awaitable<void> StateChangesCall::operator()() {
    SILK_TRACE << "StateChangesCall w/ storage: " << request_.withstorage() << " w/ txs: " << request_.withtransactions() << " START";

    // Create a never-expiring timer whose cancellation will notify our async waiting is completed
    auto coroutine_executor = co_await boost::asio::this_coro::executor;
    auto notifying_timer = steady_timer{coroutine_executor};

    std::optional<remote::StateChangeBatch> incoming_batch;

    // Register subscription to receive state change batch notifications
    StateChangeFilter filter{request_.withstorage(), request_.withtransactions()};
    const auto token = source_->subscribe([&](std::optional<remote::StateChangeBatch> batch) {
        // Make the batch handling logic execute on the scheduler associated to the RPC
        boost::asio::dispatch(coroutine_executor, [&, batch = std::move(batch)]() {
            incoming_batch = batch;
            notifying_timer.cancel();
        });
    },
                                          filter);

    // The assigned token ID must be valid.
    if (!token) {
        const auto error_message = "assigned consumer token already in use: " + std::to_string(source_->last_token());
        SILK_ERROR << "StateChanges peer: " << peer() << " subscription failed " << error_message;
        co_await agrpc::finish(responder_, grpc::Status{grpc::StatusCode::ALREADY_EXISTS, error_message});
        co_return;
    }

    // Unregister subscription whatever it happens
    auto _ = gsl::finally([&]() { source_->unsubscribe(*token); });

    bool done{false};
    while (!done) {
        // Schedule the notifying timer to expire in the infinite future i.e. never
        notifying_timer.expires_at(std::chrono::steady_clock::time_point::max());

        const auto [ec] = co_await notifying_timer.async_wait(as_tuple(use_awaitable));
        if (ec == boost::asio::error::operation_aborted) {
            // Notifying timer cancelled => incoming batch available
            if (incoming_batch) {
                const auto block_height = incoming_batch->changebatch(0).blockheight();
                SILK_DEBUG << "Sending state change batch for block: " << block_height;
                const bool write_ok = co_await agrpc::write(responder_, *incoming_batch);
                SILK_DEBUG << "State change batch for block: " << block_height << " sent [write_ok=" << write_ok << "]";
                if (!write_ok) done = true;
            } else {
                SILK_DEBUG << "Empty incoming batch notified";
                done = true;
            }
        } else {
            throw std::logic_error{"unexpected notifying timer expiration"};
        }
    }

    SILK_DEBUG << "Closing state change stream server-side";
    co_await agrpc::finish(responder_, grpc::Status::OK);
    SILK_DEBUG << "State change stream closed server-side";

    SILK_TRACE << "StateChangesCall END";
    co_return;
}

KvService::KvService(const EthereumBackEnd& backend) {
    KvVersionCall::fill_predefined_reply();
    TxCall::set_chaindata_env(backend.chaindata_env());
    StateChangesCall::set_source(backend.state_change_source());
}

void KvService::register_kv_request_calls(const ServerContext& context, remote::KV::AsyncService* service) {
    SILK_DEBUG << "KvService::register_kv_request_calls START";
    const auto grpc_context = context.server_grpc_context();
    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestVersion,
                       [](auto&&... args) -> awaitable<void> {
                           co_await KvVersionCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestTx,
                       [grpc_context](auto&&... args) -> awaitable<void> {
                           co_await TxCall{*grpc_context, std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::KV::AsyncService::RequestStateChanges,
                       [](auto&&... args) -> awaitable<void> {
                           co_await StateChangesCall{std::forward<decltype(args)>(args)...}();
                       });
    SILK_DEBUG << "KvService::register_kv_request_calls END";
}

}  // namespace silkworm::rpc
