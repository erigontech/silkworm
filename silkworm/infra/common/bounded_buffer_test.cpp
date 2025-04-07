// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bounded_buffer.hpp"

#include <chrono>
#include <thread>

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

using namespace std::this_thread;      // sleep_for, sleep_until
using namespace std::chrono_literals;  // ns, us, ms, s, h, etc.

double calculate_pi(int depth) {
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
                auto pi = calculate_pi(i % 1000);
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
    int iterations_;
    bool delay_;

  public:
    Consumer(Buffer* buffer, int iterations, bool delay)
        : container_(buffer), iterations_(iterations), delay_(delay) {}

    void operator()() {
        sleep_for(10ms);
        for (int i = 0; i < iterations_; ++i) {
            value_type item;
            if (delay_) {
                auto pi = calculate_pi(i % 1000);
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

    buffer.push_front("Hello direct");
    std::string item;
    buffer.pop_back(&item);
    CHECK(item == "Hello direct");

    Producer<BoundedBuffer<std::string>> producer(&buffer, 1, false);
    std::thread produce(producer);

    buffer.pop_back(&item);
    CHECK(item == "Hello thread 0");
    produce.join();
}

TEST_CASE("BoundedBuffer waits for an item to be popped") {
    BoundedBuffer<std::string> buffer(10);

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

    Consumer<BoundedBuffer<std::string>> consumer(&buffer, 1, false);
    std::thread consume(consumer);

    buffer.push_front("Hello");
    consume.join();
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

TEST_CASE("BoundedBuffer can terminate producer") {
    BoundedBuffer<std::string> buffer(10);
    const int iterations = 100;
    std::thread produce(Producer<BoundedBuffer<std::string>>(&buffer, iterations, true));

    buffer.terminate_and_release_all();

    produce.join();
}

TEST_CASE("BoundedBuffer can terminate consumer") {
    BoundedBuffer<std::string> buffer(10);
    const int iterations = 100;
    std::thread consume(Consumer<BoundedBuffer<std::string>>(&buffer, iterations, true));

    buffer.terminate_and_release_all();

    consume.join();
}

TEST_CASE("BoundedBuffer peek does not remove item") {
    BoundedBuffer<std::string> buffer(10);
    buffer.push_front("Hello1");
    buffer.push_front("Hello2");
    buffer.push_front("Hello3");
    buffer.push_front("Hello4");

    std::string item;
    buffer.peek_back(&item);
    CHECK(item == "Hello1");
    CHECK(buffer.size() == 4);

    buffer.pop_back(&item);
    CHECK(item == "Hello1");
    CHECK(buffer.size() == 3);

    buffer.peek_back(&item);
    CHECK(item == "Hello2");
    CHECK(buffer.size() == 3);
}

}  // namespace silkworm