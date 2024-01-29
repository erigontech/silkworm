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
#include <fstream>
#include <thread>

#include <catch2/catch.hpp>

namespace silkworm {

using namespace std::this_thread;      // sleep_for, sleep_until
using namespace std::chrono_literals;  // ns, us, ms, s, h, etc.
using std::chrono::system_clock;

template <class Buffer>
class Producer {
    typedef typename Buffer::value_type value_type;
    Buffer* container_;
    long iterations_{1};
    std::chrono::nanoseconds sleep_{10ms};

  public:
    Producer(Buffer* buffer) : container_(buffer) {}
    Producer(Buffer* buffer, long iterations, std::chrono::nanoseconds sleep)
        : container_(buffer), iterations_(iterations), sleep_(sleep) {}

    void operator()() {
        for (long i = 0; i < iterations_; ++i) {
            sleep_for(sleep_);
            container_->push_front("Hello thread " + std::to_string(i));
        }
    }
};

template <class Buffer>
class Consumer {
    typedef typename Buffer::value_type value_type;
    Buffer* container_;

  public:
    Consumer(Buffer* buffer) : container_(buffer) {}

    void operator()() {
        sleep_for(10ms);
        value_type item;
        container_->pop_back(&item);
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
    CHECK(elapsed.count() < 1000);  // less than 1 microsecond

    Producer<BoundedBuffer<std::string>> producer(&buffer);
    boost::thread produce(producer);

    buffer.pop_back(&item);
    auto finish = sw.stop();
    CHECK(item == "Hello thread 0");
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
    CHECK(elapsed.count() < 1000);  // less than 1 microsecond

    Consumer<BoundedBuffer<std::string>> consumer(&buffer);
    boost::thread consume(consumer);

    buffer.push_front("Hello");
    auto finish = sw.stop();
    CHECK(sw.since_start(finish.first).count() > 10000000);  // more than 10 milliseconds
}

TEST_CASE("BoundedBuffer cycles through the buffer") {
    BoundedBuffer<std::string> buffer(10);
    const int iterations = 1000000;
    Producer<BoundedBuffer<std::string>> producer(&buffer, iterations, 0ms);
    boost::thread produce(producer);

    std::string item;
    for (int i = 0; i < iterations; ++i) {
        buffer.pop_back(&item);
        CHECK(item == "Hello thread " + std::to_string(i));
    }
}

}  // namespace silkworm