/*
Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_MEASURE_HPP
#define SILKWORM_MEASURE_HPP

#include <chrono>

namespace silkworm {

template <typename T>
class Measure {
  public:
    using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;
    using Duration = std::chrono::nanoseconds;

    Measure() =default;
    explicit Measure(T value) { set(value); }

    T get() { return value_; }

    void set(T value) {
        value_ = value;
        timestamp_ = std::chrono::high_resolution_clock::now();
    }

    TimePoint time() { return timestamp_; }

  private:
    T value_ = {};
    TimePoint timestamp_;
};

template <typename T>
class RepeatedMeasure {
    Measure<T> prev_value_;
    Measure<T> curr_value_;
  public:
    using TimePoint = typename Measure<T>::TimePoint;
    using Duration = typename Measure<T>::Duration;

    RepeatedMeasure() =default;
    explicit RepeatedMeasure(T value) { set(value); }

    T get() { return curr_value_.get(); }

    void set(T value) {
        prev_value_ = curr_value_;
        curr_value_.set(value);
    }

    T delta() {
        return curr_value_.get() - prev_value_.get();
    }

    Duration high_res_elapsed() {
        using namespace std::chrono;
        return duration_cast<Duration>(curr_value_.time() - prev_value_.time());
    }

    auto high_res_throughput() {
        auto nano_elapsed = static_cast<unsigned long>(high_res_elapsed().count());
        if (nano_elapsed == 0) nano_elapsed = 1;
        return delta() / nano_elapsed;
    }

    std::chrono::seconds elapsed() {
        using namespace std::chrono;
        return duration_cast<seconds>(curr_value_.time() - prev_value_.time());
    }

    auto throughput() {
        auto secs_elapsed = static_cast<unsigned long>(elapsed().count());
        if (secs_elapsed == 0) secs_elapsed = 1;
        return delta() / secs_elapsed;
    }
};

}

#endif  // SILKWORM_MEASURE_HPP
