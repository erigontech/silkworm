/*
   Copyright 2023 The Silkworm Authors

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

#include "state_changes_stream.hpp"

#include <ostream>

#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/error_code.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/infra/grpc/common/util.hpp>

namespace silkworm::db::kv::grpc::client {

//! Define Asio coroutine-based completion token using error codes instead of exceptions for errors
constexpr auto use_nothrow_awaitable = boost::asio::as_tuple(boost::asio::use_awaitable);

std::chrono::milliseconds StateChangesStream::registration_interval_{kDefaultRegistrationInterval};

void StateChangesStream::set_registration_interval(std::chrono::milliseconds registration_interval) {
    StateChangesStream::registration_interval_ = registration_interval;
}

StateChangesStream::StateChangesStream(rpc::ClientContext& context, remote::KV::StubInterface* stub)
    : scheduler_(*context.io_context()),
      grpc_context_(*context.grpc_context()),
      stub_(stub),
      cache_(must_use_shared_service<api::StateCache>(scheduler_)),
      retry_timer_{scheduler_} {}

std::future<void> StateChangesStream::open() {
    return concurrency::co_spawn_sw(scheduler_, run(), boost::asio::use_future);
}

void StateChangesStream::close() {
    std::lock_guard lock{cancellation_mutex_};
    SILK_DEBUG << "Close state changes stream: emitting cancellation";
    cancellation_signal_.emit(boost::asio::cancellation_type::all);
    SILK_DEBUG << "Close state changes stream: cancellation emitted";
}

Task<void> StateChangesStream::run() {
    SILK_TRACE << "StateChangesStream::run state stream START";

    auto cancellation_slot = cancellation_signal_.slot();

    bool closed{false};
    while (!closed) {
        auto state_changes_rpc{std::make_shared<StateChangesRpc>(*stub_, grpc_context_)};

        {
            std::lock_guard lock{cancellation_mutex_};
            cancellation_slot.assign([&, state_changes_rpc](boost::asio::cancellation_type /*type*/) {
                retry_timer_.cancel();
                SILK_DEBUG << "Retry timer cancelled";

                state_changes_rpc->cancel();
                SILK_DEBUG << "State changes stream cancelled";
            });
        }

        SILK_INFO << "Registration for state changes started";
        const auto [req_ec] = co_await state_changes_rpc->request_on(scheduler_.get_executor(), request_, use_nothrow_awaitable);
        if (req_ec) {
            std::error_code request_ec{req_ec};
            if (request_ec.value() == ::grpc::StatusCode::CANCELLED || request_ec.value() == ::grpc::StatusCode::ABORTED) {
                closed = true;
                SILK_DEBUG << "State changes stream cancelled or closed by server while opening";
            } else {
                SILK_WARN << "State changes stream request error [" << req_ec.message() << "], schedule reopen";
                retry_timer_.expires_after(registration_interval_);
                const auto [ec] = co_await retry_timer_.async_wait(use_nothrow_awaitable);
                if (ec == boost::asio::error::operation_aborted) {
                    closed = true;
                    SILK_DEBUG << "State changes wait before retry cancelled";
                }
            }
            continue;
        }
        SILK_INFO << "State changes stream opened";

        std::error_code read_ec;
        remote::StateChangeBatch reply;
        while (!read_ec) {
            std::tie(read_ec, reply) = co_await state_changes_rpc->read_on(scheduler_.get_executor(), use_nothrow_awaitable);
            if (!read_ec) {
                SILK_TRACE << "State changes batch received: " << reply << "";
                cache_->on_new_block(reply);
            } else {
                if (read_ec.value() == ::grpc::StatusCode::CANCELLED || read_ec.value() == ::grpc::StatusCode::ABORTED) {
                    closed = true;
                    SILK_DEBUG << "State changes stream cancelled or closed by server while reading";
                } else {
                    SILK_WARN << "State changes stream read error [" << read_ec.message() << "], schedule reopen";
                    retry_timer_.expires_after(registration_interval_);
                    const auto [ec] = co_await retry_timer_.async_wait(use_nothrow_awaitable);
                    if (ec == boost::asio::error::operation_aborted) {
                        closed = true;
                        SILK_DEBUG << "State changes wait before retry cancelled";
                    }
                }
            }
        }
    }

    SILK_TRACE << "StateChangesStream::run state stream END";
}

}  // namespace silkworm::db::kv::grpc::client
