// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <cstdint>

namespace silkworm {

template <typename T>
class Measure {
  public:
    using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;
    using Duration = std::chrono::nanoseconds;

    Measure() = default;
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

    RepeatedMeasure() = default;
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

    double high_res_throughput() {
        auto nano_elapsed = static_cast<uint64_t>(high_res_elapsed().count());
        if (nano_elapsed == 0) nano_elapsed = 1;
        return static_cast<double>(delta()) / static_cast<double>(nano_elapsed);
    }

    template <typename DURATION = Duration>
    double high_res_throughput() {
        auto nano_elapsed = static_cast<uint64_t>(high_res_elapsed().count());
        if (nano_elapsed == 0) nano_elapsed = 1;
        using conversion = std::ratio_divide<std::nano, typename DURATION::period>;
        auto res_num = static_cast<double>(delta()) * static_cast<double>(conversion::den);
        auto res_den = static_cast<double>(nano_elapsed) * static_cast<double>(conversion::num);
        return res_num / res_den;
    }

    std::chrono::seconds elapsed() {
        using namespace std::chrono;
        return duration_cast<seconds>(curr_value_.time() - prev_value_.time());
    }

    auto throughput() {
        auto secs_elapsed = static_cast<uint64_t>(elapsed().count());
        if (secs_elapsed == 0) secs_elapsed = 1;
        return delta() / secs_elapsed;
    }
};

}  // namespace silkworm
