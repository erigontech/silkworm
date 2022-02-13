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

#include <csignal>

#include <catch2/catch.hpp>

#include <silkworm/concurrency/signal_handler.hpp>
#include <silkworm/concurrency/stoppable.hpp>
#include <silkworm/concurrency/worker.hpp>

namespace silkworm {

TEST_CASE("Worker") {
    class ThreadWorker final : public Worker {
      public:
        explicit ThreadWorker(bool should_throw = false) : should_throw_(should_throw){};
        ~ThreadWorker() override = default;
        uint32_t get_increment() const { return increment_; }

      private:
        bool should_throw_;
        std::atomic_uint32_t increment_{0};
        void work() final {
            while (wait_for_kick()) {
                increment_++;
                if (should_throw_) {
                    throw std::runtime_error("An exception");
                }
            }
        }
    };

    SECTION("No throw") {
        ThreadWorker worker(false);
        REQUIRE(worker.get_state() == Worker::State::kStopped);
        worker.start(true);
        REQUIRE(worker.get_state() == Worker::State::kKickWaiting);
        worker.kick();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        REQUIRE(worker.get_increment() == 1);
        worker.kick();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        REQUIRE(worker.get_increment() == 2);
        worker.stop(true);
        REQUIRE(worker.get_state() == Worker::State::kStopped);
    }

    SECTION("Throw") {
        ThreadWorker worker(true);
        REQUIRE(worker.get_state() == Worker::State::kStopped);
        worker.start(true);
        REQUIRE(worker.get_state() == Worker::State::kKickWaiting);
        worker.kick();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        REQUIRE(worker.get_state() == Worker::State::kStopped);
        REQUIRE(worker.has_exception() == true);
        REQUIRE_THROWS(worker.rethrow());
    }
}

TEST_CASE("Signal Handler") {
    SignalHandler::init();
    std::raise(SIGINT);
    CHECK(SignalHandler::signalled());
    SignalHandler::reset();
    CHECK(SignalHandler::signalled() == false);
}

TEST_CASE("Stoppable") {
    silkworm::Stoppable stoppable{};
    REQUIRE(stoppable.is_stopping() == false);
    REQUIRE(stoppable.stop() == true);
    REQUIRE(stoppable.stop() == false);
    REQUIRE(stoppable.is_stopping() == true);
}

}  // namespace silkworm
