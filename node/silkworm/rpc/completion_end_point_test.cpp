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

#include "completion_end_point.hpp"

#include <chrono>
#include <thread>

#include <catch2/catch.hpp>
#include <grpcpp/alarm.h>
#include <grpcpp/support/time.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using namespace std::chrono_literals;

TEST_CASE("CompletionEndPoint::poll_one", "[silkworm][rpc][completion_end_point]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    grpc::CompletionQueue queue;
    CompletionEndPoint completion_end_point{queue};

    SECTION("waiting on empty completion queue") {
        auto completion_end_point_thread = std::thread([&]() {
            while (completion_end_point.poll_one() >= 0) {
                std::this_thread::sleep_for(100us);
            }
        });
        completion_end_point.shutdown();
        CHECK_NOTHROW(completion_end_point_thread.join());
    }

// Exclude gRPC test from sanitizer builds due to data race warnings
#ifndef SILKWORM_SANITIZE
    SECTION("executing completion handler") {
        bool executed{false};
        TagProcessor tag_processor = [&completion_end_point, &executed](bool) {
            executed = true;
            completion_end_point.shutdown();
        };
        auto alarm_deadline = gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_millis(50, GPR_TIMESPAN));
        grpc::Alarm alarm;
        alarm.Set(&queue, alarm_deadline, &tag_processor);
        while (completion_end_point.poll_one() >= 0) {
            std::this_thread::sleep_for(100us);
        }
        CHECK(executed);
    }
#endif // SILKWORM_SANITIZE

    SECTION("exiting on completion queue already shutdown") {
        completion_end_point.shutdown();
        auto completion_end_point_thread = std::thread([&]() {
            while (completion_end_point.poll_one() >= 0) {
                std::this_thread::sleep_for(100us);
            }
        });
        CHECK_NOTHROW(completion_end_point_thread.join());
    }

    SECTION("stopping again after already stopped") {
        auto completion_end_point_thread = std::thread([&]() {
            while (completion_end_point.poll_one() >= 0) {
                std::this_thread::sleep_for(100us);
            }
        });
        completion_end_point.shutdown();
        CHECK_NOTHROW(completion_end_point_thread.join());
        CHECK_NOTHROW(completion_end_point.shutdown());
    }
}

TEST_CASE("CompletionEndPoint::post_one", "[silkworm][rpc][completion_end_point]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    grpc::CompletionQueue queue;
    CompletionEndPoint completion_end_point{queue};
    boost::asio::io_context io_context;
    boost::asio::io_context::work work{io_context};

    SECTION("executing completion handler") {
        bool executed{false};

        // Setup the alarm notification delivered through gRPC queue
        TagProcessor tag_processor = [&](bool) {
            executed = true;
            completion_end_point.shutdown();
            io_context.stop();
        };
        auto alarm_deadline = gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_millis(50, GPR_TIMESPAN));
        grpc::Alarm alarm;
        alarm.Set(&queue, alarm_deadline, &tag_processor);

        // Start the thread polling the gRPC queue
        auto completion_runner_thread = std::thread([&]() {
            bool stopped{false};
            while (!stopped) {
                stopped = completion_end_point.post_one(io_context);
            }
        });

        // Run the Asio scheduler executing the completion handler
        io_context.run();

        CHECK_NOTHROW(completion_runner_thread.join());
        CHECK(executed);
    }
}

} // namespace silkworm::rpc
