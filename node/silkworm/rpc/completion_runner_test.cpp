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

#include "completion_runner.hpp"

#include <future>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <catch2/catch.hpp>
#include <grpcpp/alarm.h>
#include <grpcpp/support/time.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;

TEST_CASE("CompletionRunner", "[silkworm][rpc][completion_runner]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);

    SECTION("waiting on empty completion queue") {
        grpc::CompletionQueue queue;
        boost::asio::io_context io_context;
        CompletionRunner completion_runner{queue, io_context};
        auto completion_runner_thread = std::thread([&]() { completion_runner.run(); });
        std::this_thread::yield();
        completion_runner.stop();
        CHECK_NOTHROW(completion_runner_thread.join());
    }

    SECTION("posting handler completion to I/O execution context") {
        grpc::CompletionQueue queue;
        boost::asio::io_context io_context;
        boost::asio::io_context::work work{io_context};
        CompletionRunner completion_runner{queue, io_context};
        auto io_context_thread = std::thread([&]() { io_context.run(); });
        auto completion_runner_thread = std::thread([&]() { completion_runner.run(); });
        std::this_thread::yield();
        std::promise<void> p;
        std::future<void> f = p.get_future();
        class AsyncCompletionHandler {
        public:
            explicit AsyncCompletionHandler(std::promise<void>& p) : p_(p) {}
            void operator()(bool /*ok*/) { p_.set_value(); };
        private:
            std::promise<void>& p_;
        };
        AsyncCompletionHandler handler{p};
        TagProcessor tag_processor = handler;
        auto alarm_deadline = gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_millis(50, GPR_TIMESPAN));
        grpc::Alarm alarm;
        alarm.Set(&queue, alarm_deadline, &tag_processor);
        f.get();
        completion_runner.stop();
        io_context.stop();
        CHECK_NOTHROW(io_context_thread.join());
        CHECK_NOTHROW(completion_runner_thread.join());
    }

    SECTION("exiting on completion queue already shutdown") {
        grpc::CompletionQueue queue;
        boost::asio::io_context io_context;
        CompletionRunner completion_runner{queue, io_context};
        completion_runner.stop();
        auto completion_runner_thread = std::thread([&]() { completion_runner.run(); });
        std::this_thread::yield();
        CHECK_NOTHROW(completion_runner_thread.join());
    }

    SECTION("stopping again after already stopped") {
        grpc::CompletionQueue queue;
        boost::asio::io_context io_context;
        CompletionRunner completion_runner{queue, io_context};
        auto completion_runner_thread = std::thread([&]() { completion_runner.run(); });
        std::this_thread::yield();
        completion_runner.stop();
        CHECK_NOTHROW(completion_runner_thread.join());
        CHECK_NOTHROW(completion_runner.stop());
    }
}

} // namespace silkworm::rpc
