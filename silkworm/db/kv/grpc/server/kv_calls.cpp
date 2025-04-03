// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "kv_calls.hpp"

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <gsl/util>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/common/util.hpp>

namespace silkworm::db::kv::grpc::server {

using boost::asio::as_tuple;
using namespace boost::asio::experimental::awaitable_operators;
using boost::asio::steady_timer;
using boost::asio::use_awaitable;

api::Version higher_version_ignoring_patch(api::Version lhs, api::Version rhs) {
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
    const auto max_version = higher_version_ignoring_patch(kDbSchemaVersion, api::kCurrentVersion);
    KvVersionCall::response_.set_major(std::get<0>(max_version));
    KvVersionCall::response_.set_minor(std::get<1>(max_version));
    KvVersionCall::response_.set_patch(std::get<2>(max_version));
}

Task<void> KvVersionCall::operator()() {
    SILK_TRACE << "KvVersionCall START";
    co_await agrpc::finish(responder_, response_, ::grpc::Status::OK);
    SILK_TRACE << "KvVersionCall END version: " << response_.major() << "." << response_.minor() << "." << response_.patch();
}

std::chrono::milliseconds TxCall::max_ttl_duration_{kMaxTxDuration};

void TxCall::set_max_ttl_duration(const std::chrono::milliseconds& max_ttl_duration) {
    TxCall::max_ttl_duration_ = max_ttl_duration;
}

Task<void> TxCall::operator()(ROAccess chaindata) {
    SILK_TRACE << "TxCall peer: " << peer() << " MDBX readers: " << (*chaindata).get_info().mi_numreaders;

    ::grpc::Status status{::grpc::Status::OK};
    try {
        // Assign a monotonically increasing unique ID to remote transaction
        const auto tx_id = ++next_tx_id_;

        // Create a new read-only transaction.
        read_only_txn_ = chaindata.start_ro_tx();
        SILK_DEBUG << "TxCall peer: " << peer() << " started tx: " << tx_id << " view: " << read_only_txn_->id();

        // Send an unsolicited message containing the transaction ID and view ID (i.e. MDBX txn ID)
        remote::Pair tx_id_pair;
        tx_id_pair.set_tx_id(tx_id);
        tx_id_pair.set_view_id(read_only_txn_->id());
        if (!co_await agrpc::write(responder_, tx_id_pair)) {
            SILK_WARN << "Tx closed by peer: " << server_context_.peer() << " error: write failed";
            co_await agrpc::finish(responder_, ::grpc::Status::OK);
            co_return;
        }
        SILK_DEBUG << "TxCall announcement with txid=" << read_only_txn_->id() << " sent";

        // Create guard timers to 1) close idle transactions 2) close and reopen long-lived transactions.
        boost::asio::steady_timer max_idle_alarm{grpc_context_}, max_ttl_alarm{grpc_context_};
        std::chrono::steady_clock::time_point max_idle_deadline{std::chrono::steady_clock::now() + max_idle_duration_};
        std::chrono::steady_clock::time_point max_ttl_deadline{std::chrono::steady_clock::now() + max_ttl_duration_};
        max_idle_alarm.expires_at(max_idle_deadline);
        max_ttl_alarm.expires_at(max_ttl_deadline);

        // Setup read and write streams
        agrpc::GrpcStream read_stream{grpc_context_}, write_stream{grpc_context_};
        remote::Cursor request;
        read_stream.initiate(agrpc::read, responder_, request);

        const auto read = [&]() -> Task<void> {
            try {
                while (co_await read_stream.next()) {
                    // Handle incoming request from client
                    remote::Pair response{};
                    handle(&request, response);
                    // Schedule write for response
                    write_stream.initiate(agrpc::write, responder_, std::move(response));
                    // Reset request and schedule subsequent read
                    request.Clear();
                    read_stream.initiate(agrpc::read, responder_, request);
                    // Update idle timer deadline every time we receive an incoming request
                    max_idle_deadline += max_idle_duration_;
                }
            } catch (const mdbx::exception& e) {
                const auto error_message = "start tx failed: " + std::string{e.what()};
                SILK_ERROR << "Tx peer: " << peer() << " " << error_message;
                status = ::grpc::Status{::grpc::StatusCode::RESOURCE_EXHAUSTED, error_message};
            } catch (const rpc::server::CallException& ce) {
                status = ce.status();
            } catch (const boost::system::system_error& se) {
                if (se.code() != boost::asio::error::operation_aborted) {
                    status = ::grpc::Status{::grpc::StatusCode::INTERNAL, se.what()};
                }
            } catch (const std::exception& exc) {
                status = ::grpc::Status{::grpc::StatusCode::INTERNAL, exc.what()};
            }
        };
        const auto write = [&]() -> Task<void> {
            while (co_await write_stream.next()) {
            }
        };
        const auto max_idle_timer = [&]() -> Task<void> {
            while (true) {
                const auto [ec] = co_await max_idle_alarm.async_wait(as_tuple(use_awaitable));
                if (!ec) {
                    const auto error_msg{"no incoming request in " + std::to_string(max_idle_duration_.count()) + " ms"};
                    SILK_WARN << "Tx idle peer: " << server_context_.peer() << " error: " << error_msg;
                    status = ::grpc::Status{::grpc::StatusCode::DEADLINE_EXCEEDED, error_msg};
                    break;
                }
            }
        };
        const auto max_ttl_timer = [&]() -> Task<void> {
            while (true) {
                const auto [ec] = co_await max_ttl_alarm.async_wait(as_tuple(use_awaitable));
                if (!ec) {
                    handle_max_ttl_timer_expired(chaindata);
                    max_ttl_deadline += max_ttl_duration_;
                }
            }
        };

        co_await (read() || write() || max_idle_timer() || max_ttl_timer());

        SILK_DEBUG << "TxCall peer: " << peer() << " read/write loop completed";
    } catch (const mdbx::exception& e) {
        const auto error_message = "start tx failed: " + std::string{e.what()};
        SILK_ERROR << "Tx peer: " << peer() << " " << error_message;
        status = ::grpc::Status{::grpc::StatusCode::RESOURCE_EXHAUSTED, error_message};
    } catch (const rpc::server::CallException& ce) {
        status = ce.status();
    } catch (const std::exception& exc) {
        status = ::grpc::Status{::grpc::StatusCode::INTERNAL, exc.what()};
    }

    co_await agrpc::finish(responder_, status);

    SILK_TRACE << "TxCall END peer: " << peer() << " status: " << status;
}

void TxCall::handle(const remote::Cursor* request, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle " << this << " request: " << request << " START";

    // Handle separately main use cases: cursor OPEN, cursor CLOSE and any other cursor operation.
    const auto cursor_op = request->op();
    if (cursor_op == remote::Op::OPEN || cursor_op == remote::Op::OPEN_DUP_SORT) {
        handle_cursor_open(request, response);
    } else if (cursor_op == remote::Op::CLOSE) {
        handle_cursor_close(request);
    } else {
        handle_cursor_operation(request, response);
    }

    SILK_TRACE << "TxCall::handle " << this << " request: " << request << " END";
}

void TxCall::handle_cursor_open(const remote::Cursor* request, remote::Pair& response) {
    const std::string& bucket_name = request->bucket_name();

    // Bucket name must be a valid MDBX map name
    if (!has_map(read_only_txn_, bucket_name.c_str())) {
        const auto err = "unknown bucket: " + request->bucket_name();
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << err;
        throw_with_error(::grpc::Status{::grpc::StatusCode::INVALID_ARGUMENT, err});
    }

    // The number of opened cursors shall not exceed the maximum threshold.
    if (cursors_.size() == kMaxTxCursors) {
        const auto err = "maximum cursors per txn reached: " + std::to_string(cursors_.size());
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << err;
        throw_with_error(::grpc::Status{::grpc::StatusCode::RESOURCE_EXHAUSTED, err});
    }

    // Create a new database cursor tracking also bucket name (needed for reopening). We create a read-only dup-sort
    // cursor so that it works for both single-value and multi-value tables.
    const MapConfig map_config{
        .name = bucket_name.c_str(),
        .value_mode = request->op() == remote::Op::OPEN ? ::mdbx::value_mode::single : ::mdbx::value_mode::multi,
    };
    auto cursor = read_only_txn_.ro_cursor_dup_sort(map_config);
    const auto [cursor_it, inserted] = cursors_.insert({++last_cursor_id_, TxCursor{std::move(cursor), bucket_name}});

    SILKWORM_ASSERT(cursor_it->first == last_cursor_id_);

    // The assigned cursor ID shall not be already in use (after cursor ID wrapping).
    if (!inserted) {
        const auto error_message = "assigned cursor ID already in use: " + std::to_string(last_cursor_id_);
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        throw_with_error(::grpc::Status{::grpc::StatusCode::ALREADY_EXISTS, error_message});
    }

    // Send the assigned cursor ID back to the client.
    response.set_cursor_id(cursor_it->first);
    SILK_DEBUG << "Tx peer: " << peer() << " opened cursor: " << response.cursor_id();
}

void TxCall::handle_cursor_operation(const remote::Cursor* request, remote::Pair& response) {
    const auto cursor_it = cursors_.find(request->cursor());
    if (cursor_it == cursors_.end()) {
        const auto error_message = "unknown cursor: " + std::to_string(request->cursor());
        SILK_ERROR << "Tx peer: " << peer() << " op=" << remote::Op_Name(request->op()) << " " << error_message;
        throw_with_error(::grpc::Status{::grpc::StatusCode::INVALID_ARGUMENT, error_message});
    }
    auto& cursor = cursor_it->second.cursor;
    try {
        handle_operation(request, *cursor, response);
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
        throw_with_error(::grpc::Status{::grpc::StatusCode::INVALID_ARGUMENT, error_message});
    }
    cursors_.erase(cursor_it);
    SILK_DEBUG << "Tx peer: " << peer() << " closed cursor: " << request->cursor();
}

void TxCall::handle_operation(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response) {
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

void TxCall::handle_max_ttl_timer_expired(ROAccess chaindata) {
    // Save the whole state of the transaction (i.e. all cursor positions)
    std::vector<CursorPosition> positions;
    const bool save_success = save_cursors(positions);
    if (!save_success) {
        throw_with_internal_error("cannot save state of cursors");
    }
    SILK_DEBUG << "Tx peer: " << peer() << " #cursors: " << cursors_.size() << " saved";

    // Close and reopen to avoid long-lived transactions (resource-consuming for MDBX)
    read_only_txn_.abort();
    read_only_txn_ = chaindata.start_ro_tx();

    // Restore the whole state of the transaction (i.e. all cursor positions)
    const bool restore_success = restore_cursors(positions);
    if (!restore_success) {
        throw_with_internal_error("cannot restore state of cursors");
    }
    SILK_DEBUG << "Tx peer: " << peer() << " #cursors: " << cursors_.size() << " restored";
}

bool TxCall::save_cursors(std::vector<CursorPosition>& positions) {
    for (const auto& [cursor_id, tx_cursor] : cursors_) {
        if (tx_cursor.cursor->is_dangling()) {
            // Cursor is open but never used so no position to store, just be sure to reopen it
            positions.emplace_back();
        } else {
            const auto result = tx_cursor.cursor->current(/*throw_notfound=*/false);
            SILK_DEBUG << "Tx save cursor: " << cursor_id << " result: " << detail::dump_mdbx_result(result);
            if (!result) {
                return false;
            }
            mdbx::slice key = result.key;
            mdbx::slice value = result.value;
            positions.emplace_back(CursorPosition{key.as_string(), value.as_string()});
        }
    }

    return true;
}

bool TxCall::restore_cursors(std::vector<CursorPosition>& positions) {
    SILKWORM_ASSERT(positions.size() == cursors_.size());

    auto position_iterator = positions.begin();

    for (auto& [cursor_id, tx_cursor] : cursors_) {
        const std::string& bucket_name = tx_cursor.bucket_name;
        const MapConfig map_config{bucket_name.c_str()};

        // Bind each cursor to the renewed transaction.
        auto& cursor = tx_cursor.cursor;
        cursor->bind(read_only_txn_, map_config);

        const auto& [current_key, current_value] = *position_iterator;
        ++position_iterator;
        SILKWORM_ASSERT(current_key.has_value() == current_value.has_value());
        if (!current_key && !current_value) {
            continue;
        }

        SILK_DEBUG << "Tx restore cursor " << cursor_id << " current_key: " << *current_key << " current_value: " << *current_value;
        mdbx::slice key{current_key->c_str()};

        // Restore each cursor saved position.
        if (cursor->is_multi_value()) {
            /* multi-value table */
            mdbx::slice value{current_value->c_str()};
            const auto lbm_result = cursor->lower_bound_multivalue(key, value, /*throw_notfound=*/false);
            SILK_DEBUG << "Tx restore cursor " << cursor_id << " for: " << bucket_name << " lbm_result: " << detail::dump_mdbx_result(lbm_result);
            // It may happen that key where we stopped disappeared after transaction reopen, then just move to next key
            if (!lbm_result) {
                const auto next_result = cursor->to_next(/*throw_notfound=*/false);
                SILK_DEBUG << "Tx restore cursor " << cursor_id << " for: " << bucket_name << " next_result: " << detail::dump_mdbx_result(next_result);
                if (!next_result) {
                    return false;
                }
            }
        } else {
            /* single-value table */
            const auto result = (key.empty()) ? cursor->to_first(/*throw_notfound=*/false) : cursor->lower_bound(key, /*throw_notfound=*/false);
            SILK_DEBUG << "Tx restore cursor " << cursor_id << " for: " << bucket_name << " result: " << detail::dump_mdbx_result(result);
            if (!result) {
                return false;
            }
        }
    }

    return true;
}

void TxCall::handle_first(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_first " << this << " START";

    const auto result = cursor.to_first(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx FIRST result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_first " << this << " END";
}

void TxCall::handle_first_dup(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_first_dup " << this << " START";

    const auto result = cursor.to_current_first_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx FIRST_DUP result: " << detail::dump_mdbx_result(result);

    // Do not use `operator bool(result)` to avoid MDBX Assertion `!done || (bool(key) && bool(value))' failed
    if (result.done && result.value) {
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_first_dup " << this << " END";
}

void TxCall::handle_seek(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_seek " << this << " START";
    mdbx::slice key{request->k()};

    const auto result = (key.empty()) ? cursor.to_first(/*throw_notfound=*/false) : cursor.lower_bound(key, /*throw_notfound=*/false);
    SILK_DEBUG << "Tx SEEK result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_seek " << this << " END";
}

void TxCall::handle_seek_both(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response) {
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

void TxCall::handle_seek_exact(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_seek_exact " << this << " START";
    mdbx::slice key{request->k()};

    const bool found = cursor.seek(key);
    SILK_DEBUG << "Tx SEEK_EXACT found: " << std::boolalpha << found;

    if (found) {
        const auto result = cursor.current(/*throw_notfound=*/false);
        SILK_DEBUG << "Tx SEEK_EXACT result: " << detail::dump_mdbx_result(result);

        if (result) {
            response.set_k(request->k());
            response.set_v(result.value.as_string());
        }
    }

    SILK_TRACE << "TxCall::handle_seek_exact " << this << " END";
}

void TxCall::handle_seek_both_exact(const remote::Cursor* request, ROCursorDupSort& cursor, remote::Pair& response) {
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

void TxCall::handle_current(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_current " << this << " START";

    const auto result = cursor.current(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx CURRENT result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_current " << this << " END";
}

void TxCall::handle_last(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_last " << this << " START";

    const auto result = cursor.to_last(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx LAST result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_last " << this << " END";
}

void TxCall::handle_last_dup(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_last_dup " << this << " START";

    const auto result = cursor.to_current_last_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx LAST_DUP result: " << detail::dump_mdbx_result(result);

    // Do not use `operator bool(result)` to avoid MDBX Assertion `!done || (bool(key) && bool(value))' failed
    if (result.done && result.value) {
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_last_dup " << this << " END";
}

void TxCall::handle_next(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_next " << this << " START";

    const auto result = cursor.to_next(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx NEXT result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_next " << this << " END";
}

void TxCall::handle_next_dup(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_next_dup " << this << " START";

    const auto result = cursor.to_current_next_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx NEXT_DUP result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_next_dup " << this << " END";
}

void TxCall::handle_next_no_dup(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_next_no_dup " << this << " START";

    const auto result = cursor.to_next_first_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx NEXT_NO_DUP result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_next_no_dup " << this << " END";
}

void TxCall::handle_prev(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_prev " << this << " START";

    const auto result = cursor.to_previous(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx PREV result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_prev " << this << " END";
}

void TxCall::handle_prev_dup(ROCursorDupSort& cursor, remote::Pair& response) {
    SILK_TRACE << "TxCall::handle_prev_dup " << this << " START";

    const auto result = cursor.to_current_prev_multi(/*throw_notfound=*/false);
    SILK_DEBUG << "Tx PREV_DUP result: " << detail::dump_mdbx_result(result);

    if (result) {
        response.set_k(result.key.as_string());
        response.set_v(result.value.as_string());
    }

    SILK_TRACE << "TxCall::handle_prev_dup " << this << " END";
}

void TxCall::handle_prev_no_dup(ROCursorDupSort& cursor, remote::Pair& response) {
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
    throw_with_error(::grpc::Status{::grpc::StatusCode::INTERNAL, error_message});
}

void TxCall::throw_with_internal_error(const std::string& message) {
    throw_with_error(::grpc::Status{::grpc::StatusCode::INTERNAL, message});
}

void TxCall::throw_with_error(::grpc::Status status) {
    SILK_ERROR << "Tx peer: " << peer() << " " << status.error_message();
    throw rpc::server::CallException{std::move(status)};
}

Task<void> StateChangesCall::operator()(StateChangeCollection* source) {
    SILK_TRACE << "StateChangesCall w/ storage: " << request_.with_storage() << " w/ txs: " << request_.with_transactions() << " START";

    // Create a never-expiring timer whose cancellation will notify our async waiting is completed
    auto coroutine_executor = co_await boost::asio::this_coro::executor;
    auto notifying_timer = steady_timer{coroutine_executor};

    std::optional<remote::StateChangeBatch> incoming_batch;

    // Register subscription to receive state change batch notifications
    StateChangeConsumer state_change_consumer = [&](std::optional<remote::StateChangeBatch> batch) {
        // Make the batch handling logic execute on the scheduler associated to the RPC
        boost::asio::dispatch(coroutine_executor, [&, batch = std::move(batch)]() {
            incoming_batch = batch;
            notifying_timer.cancel();
        });
    };
    StateChangeFilter filter{request_.with_storage(), request_.with_transactions()};
    const auto token = source->subscribe(state_change_consumer, filter);

    // The assigned token ID must be valid.
    if (!token) {
        const auto error_message = "assigned consumer token already in use: " + std::to_string(source->last_token());
        SILK_ERROR << "StateChanges peer: " << peer() << " subscription failed " << error_message;
        co_await agrpc::finish(responder_, ::grpc::Status{::grpc::StatusCode::ALREADY_EXISTS, error_message});
        co_return;
    }

    // Unregister subscription whatever it happens
    [[maybe_unused]] auto _ = gsl::finally([&]() { source->unsubscribe(*token); });

    bool done{false};
    while (!done) {
        // Schedule the notifying timer to expire in the infinite future i.e. never
        notifying_timer.expires_at(std::chrono::steady_clock::time_point::max());

        const auto [ec] = co_await notifying_timer.async_wait(as_tuple(use_awaitable));
        if (ec == boost::asio::error::operation_aborted) {
            // Notifying timer cancelled => incoming batch available
            if (incoming_batch) {
                const auto block_num = incoming_batch->change_batch(0).block_height();
                SILK_DEBUG << "Sending state change batch for block: " << block_num;
                const bool write_ok = co_await agrpc::write(responder_, *incoming_batch);
                SILK_DEBUG << "State change batch for block: " << block_num << " sent [write_ok=" << write_ok << "]";
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
    co_await agrpc::finish(responder_, ::grpc::Status::OK);
    SILK_DEBUG << "State change stream closed server-side";

    SILK_TRACE << "StateChangesCall END";
    co_return;
}

Task<void> SnapshotsCall::operator()() {
    SILK_TRACE << "SnapshotsCall START";
    remote::SnapshotsReply response;
    // TODO(canepat) implement properly
    co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
    SILK_TRACE << "SnapshotsCall END #blocks_files: " << response.blocks_files_size() << " #history_files: " << response.history_files_size();
}

Task<void> HistorySeekCall::operator()() {
    SILK_TRACE << "HistorySeekCall START";
    remote::HistorySeekReply response;
    // TODO(canepat) implement properly
    co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
    SILK_TRACE << "HistorySeekCall END ok: " << response.ok() << " value: " << response.v();
}

Task<void> GetLatestCall::operator()() {
    SILK_TRACE << "GetLatestCall START";
    remote::GetLatestReply response;
    // TODO(canepat) implement properly
    co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
    SILK_TRACE << "GetLatestCall END ok: " << response.ok() << " value: " << response.v();
}

Task<void> IndexRangeCall::operator()() {
    SILK_TRACE << "IndexRangeCall START";
    remote::IndexRangeReply response;
    // TODO(canepat) implement properly
    co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
    SILK_TRACE << "IndexRangeCall END #timestamps: " << response.timestamps_size() << " next_page_token: " << response.next_page_token();
}

Task<void> HistoryRangeCall::operator()() {
    SILK_TRACE << "HistoryRangeCall START";
    remote::Pairs response;
    // TODO(canepat) implement properly
    co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
    SILK_TRACE << "HistoryRangeCall END #keys: " << response.keys_size() << " #values: " << response.values_size()
               << " next_page_token: " << response.next_page_token();
}

Task<void> RangeAsOfCall::operator()() {
    SILK_TRACE << "RangeAsOfCall START";
    remote::Pairs response;
    // TODO(canepat) implement properly
    co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
    SILK_TRACE << "RangeAsOfCall END #keys: " << response.keys_size() << " #values: " << response.values_size()
               << " next_page_token: " << response.next_page_token();
}

}  // namespace silkworm::db::kv::grpc::server
