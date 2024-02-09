/*
   Copyright 2024 The Silkworm Authors

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

#include "bounded_buffer.hpp"

#include <chrono>
#include <thread>

#include <catch2/catch.hpp>

#include <silkworm/infra/common/stopwatch.hpp>

namespace silkworm {

using namespace std::this_thread;      // sleep_for, sleep_until
using namespace std::chrono_literals;  // ns, us, ms, s, h, etc.
using std::chrono::system_clock;

double CalculatePi(int depth) {
    double pi = 0.0;
    for (int i = 0; i < depth; ++i) {
        auto numerator = static_cast<double>(((i % 2) * 2) - 1);
        auto denominator = static_cast<double>((2 * i) - 1);
        pi += numerator / denominator;
    }
    return (pi - 1.0) * 4;
}

template <class Buffer>
class Producer {
    Buffer* container_;
    int iterations_;
    bool delay_;

  public:
    Producer(Buffer* buffer, int iterations, bool delay)
        : container_(buffer), iterations_(iterations), delay_(delay) {}

    void operator()() {
        sleep_for(10ms);
        for (int i = 0; i < iterations_; ++i) {
            if (delay_) {
                auto pi = CalculatePi(i % 1000);
                if (pi < 3.14) {
                    sleep_for(1ns);
                }
            }
            container_->push_front("Hello thread " + std::to_string(i));
        }
    }
};

template <class Buffer>
class Consumer {
    using value_type = typename Buffer::value_type;
    Buffer* container_;
    long iterations_;
    bool delay_;

  public:
    Consumer(Buffer* buffer, long iterations, bool delay)
        : container_(buffer), iterations_(iterations), delay_(delay) {}

    void operator()() {
        sleep_for(10ms);
        for (int i = 0; i < iterations_; ++i) {
            value_type item;
            if (delay_) {
                auto pi = CalculatePi(i % 1000);
                if (pi < 3.14) {
                    sleep_for(1ns);
                }
            }
            container_->pop_back(&item);
        }
    }
};

TEST_CASE("BoundedBuffer can initialize") {
    BoundedBuffer<int> buffer(10);
    CHECK(buffer.size() == 0);
    CHECK(buffer.capacity() == 10);
}

TEST_CASE("BoundedBuffer add and remove") {
    BoundedBuffer<std::string> buffer(10);
    CHECK(buffer.size() == 0);
    CHECK(buffer.capacity() == 10);

    buffer.push_front("Hello");

    CHECK(buffer.size() == 1);
    std::string item;
    buffer.pop_back(&item);
    CHECK(item == "Hello");
    CHECK(buffer.size() == 0);
}

TEST_CASE("BoundedBuffer waits for an item to be added") {
    BoundedBuffer<std::string> buffer(10);
    StopWatch sw;

    buffer.push_front("Hello direct");
    sw.start();
    std::string item;
    buffer.pop_back(&item);
    auto [_, elapsed]{sw.lap()};
    CHECK(item == "Hello direct");
    // CHECK(elapsed.count() < 3000);  // less than 3 microsecond

    Producer<BoundedBuffer<std::string>> producer(&buffer, 1, false);
    std::thread produce(producer);

    buffer.pop_back(&item);
    auto finish = sw.stop();
    CHECK(item == "Hello thread 0");
    produce.join();
    CHECK(sw.since_start(finish.first).count() > 10000000);  // more than 10 milliseconds
}

TEST_CASE("BoundedBuffer waits for an item to be popped") {
    BoundedBuffer<std::string> buffer(10);
    StopWatch sw;

    sw.start();
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    buffer.push_front("Hello");
    auto [_, elapsed]{sw.lap()};
    // CHECK(elapsed.count() < 3000);  // less than 3 microsecond

    Consumer<BoundedBuffer<std::string>> consumer(&buffer, 1, false);
    std::thread consume(consumer);

    buffer.push_front("Hello");
    auto finish = sw.stop();
    consume.join();
    CHECK(sw.since_start(finish.first).count() > 10000000);  // more than 10 milliseconds
}

TEST_CASE("BoundedBuffer multiple cycles over the buffer with delayed producer") {
    BoundedBuffer<std::string> buffer(10);
    const int iterations = 100000;
    Producer<BoundedBuffer<std::string>> producer(&buffer, iterations, true);
    Consumer<BoundedBuffer<std::string>> consumer(&buffer, iterations, false);
    std::thread produce(producer);
    std::thread consume(consumer);

    produce.join();
    consume.join();
}

TEST_CASE("BoundedBuffer multiple cycles over the buffer with delayed consumer") {
    BoundedBuffer<std::string> buffer(10);
    const int iterations = 100000;
    std::thread produce(Producer<BoundedBuffer<std::string>>(&buffer, iterations, false));
    std::thread consume(Consumer<BoundedBuffer<std::string>>(&buffer, iterations, true));

    produce.join();
    consume.join();
}

}  // namespace silkworm