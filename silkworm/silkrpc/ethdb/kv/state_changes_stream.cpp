/*
    Copyright 2022 The Silkrpc Authors

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
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/error_code.hpp>
#include <grpc/grpc.h>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/grpc/util.hpp>

namespace silkrpc::ethdb::kv {

//! Define Asio coroutine-based completion token using error codes instead of exceptions for errors
constexpr auto use_nothrow_awaitable = boost::asio::as_tuple(boost::asio::use_awaitable);

boost::posix_time::milliseconds StateChangesStream::registration_interval_{kDefaultRegistrationInterval};

void StateChangesStream::set_registration_interval(boost::posix_time::milliseconds registration_interval) {
    StateChangesStream::registration_interval_ = registration_interval;
}

StateChangesStream::StateChangesStream(Context& context, remote::KV::StubInterface* stub)
    : scheduler_(*context.io_context()),
      grpc_context_(*context.grpc_context()),
      cache_(context.state_cache().get()),
      stub_(stub),
      retry_timer_{scheduler_} {}

std::future<void> StateChangesStream::open() {
    return boost::asio::co_spawn(scheduler_, run(), boost::asio::use_future);
}

void StateChangesStream::close() {
    SILKRPC_DEBUG << "Close state changes stream: emitting cancellation\n";
    cancellation_signal_.emit(boost::asio::cancellation_type::all);
    SILKRPC_WARN << "Close state changes stream: cancellation emitted\n";
}

boost::asio::awaitable<void> StateChangesStream::run() {
    SILKRPC_TRACE << "StateChangesStream::run state stream START\n";

    auto cancellation_slot = cancellation_signal_.slot();

    bool cancelled{false};
    while (!cancelled) {
        auto state_changes_rpc{std::make_shared<StateChangesRpc>(*stub_, grpc_context_)};

        cancellation_slot.assign([&, state_changes_rpc](boost::asio::cancellation_type /*type*/) {
            retry_timer_.cancel();
            SILKRPC_DEBUG << "Retry timer cancelled\n";

            state_changes_rpc->cancel();
            SILKRPC_WARN << "State changes stream cancelled\n";
        });

        SILKRPC_INFO << "Registration for state changes started\n";
        const auto [req_ec] = co_await state_changes_rpc->request_on(scheduler_.get_executor(), request_, use_nothrow_awaitable);
        if (req_ec) {
            if (std::error_code(req_ec).value() == grpc::StatusCode::CANCELLED) {
                cancelled = true;
                SILKRPC_DEBUG << "State changes stream cancelled immediately after request cancelled\n";
            } else {
                SILKRPC_WARN << "State changes stream request error [" << req_ec.message() << "], schedule reopen\n";
                retry_timer_.expires_from_now(registration_interval_);
                const auto [ec] = co_await retry_timer_.async_wait(use_nothrow_awaitable);
                if (ec == boost::asio::error::operation_aborted) {
                    cancelled = true;
                    SILKRPC_DEBUG << "State changes wait before retry cancelled\n";
                }
            }
            continue;
        }
        SILKRPC_INFO << "State changes stream opened\n";

        std::error_code read_ec;
        remote::StateChangeBatch reply;
        while (!read_ec) {
            std::tie(read_ec, reply) = co_await state_changes_rpc->read_on(scheduler_.get_executor(), use_nothrow_awaitable);
            if (!read_ec) {
                SILKRPC_INFO << "State changes batch received: " << reply << "\n";
                cache_->on_new_block(reply);
            } else {
                if (read_ec.value() == grpc::StatusCode::CANCELLED) {
                    cancelled = true;
                    SILKRPC_DEBUG << "State changes stream cancelled immediately after read cancelled\n";
                } else {
                    SILKRPC_WARN << "State changes stream read error [" << read_ec.message() << "], schedule reopen\n";
                    retry_timer_.expires_from_now(registration_interval_);
                    const auto [ec] = co_await retry_timer_.async_wait(use_nothrow_awaitable);
                    if (ec == boost::asio::error::operation_aborted) {
                        cancelled = true;
                        SILKRPC_DEBUG << "State changes wait before retry cancelled\n";
                    }
                }
            }
        }
    }

    SILKRPC_TRACE << "StateChangesStream::run state stream END\n";
}

} // namespace silkrpc::ethdb::kv
