/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "stopwatch.hpp"

namespace silkworm {

StopWatch::TimePoint StopWatch::start(bool with_reset) noexcept {
    using namespace std::chrono_literals;
    if (with_reset) {
        reset();
    }

    if (started_) {
        return start_time_;
    }

    started_ = true;
    if (start_time_ == TimePoint()) {
        start_time_ = std::chrono::high_resolution_clock::now();
    }
    if (!laps_.empty()) {
        auto& [t, d] = laps_.back();
        laps_.emplace_back(start_time_, std::chrono::duration_cast<Duration>(start_time_ - t));
    } else {
        laps_.emplace_back(start_time_, std::chrono::duration_cast<Duration>(0s));
    }
    return start_time_;
}

std::pair<StopWatch::TimePoint, StopWatch::Duration> StopWatch::lap() noexcept {
    if (!started_ || laps_.empty()) {
        return {};
    }
    const auto lap_time{std::chrono::high_resolution_clock::now()};
    const auto& [t, d] = laps_.back();
    laps_.emplace_back(lap_time, std::chrono::duration_cast<Duration>(lap_time - t));
    return laps_.back();
}

StopWatch::Duration StopWatch::lap_duration() noexcept {
    auto [tp, duration] = lap();
    return duration;
}

StopWatch::Duration StopWatch::since_start(const TimePoint& origin) noexcept {
    if (!started_) {
        return {};
    }
    return Duration(origin - start_time_);
}

std::pair<StopWatch::TimePoint, StopWatch::Duration> StopWatch::stop() noexcept {
    if (!started_) {
        return {};
    }
    auto ret{lap()};
    started_ = false;
    return ret;
}

void StopWatch::reset() noexcept {
    (void)stop();
    start_time_ = TimePoint();
    std::vector<std::pair<TimePoint, Duration>>().swap(laps_);
}

std::string StopWatch::format(Duration duration) noexcept {
    using days = std::chrono::duration<int, std::ratio<86400>>;
    auto d = std::chrono::duration_cast<days>(duration);
    duration -= d;
    auto h = std::chrono::duration_cast<std::chrono::hours>(duration);
    duration -= h;
    auto m = std::chrono::duration_cast<std::chrono::minutes>(duration);
    duration -= m;
    auto s = std::chrono::duration_cast<std::chrono::seconds>(duration);
    duration -= s;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    duration -= ms;
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(duration);
    duration -= us;

    std::ostringstream os;
    if (d.count()) {
        os << d.count() << "d";
        if (h.count() || m.count() || s.count()) {
            os << " ";
        }
    }
    if (h.count()) {
        os << h.count() << "h";
        if (m.count() || s.count()) {
            os << " ";
        }
    }
    if (m.count()) {
        os << m.count() << "m";
        if (s.count() || ms.count()) {
            os << " ";
        }
    }
    if (s.count()) {
        os << s.count() << "s";
    }
    if (!(d.count() || h.count() || m.count()) && (ms.count() || us.count())) {
        if(s.count()) {
            os << " ";
        }
        if (ms.count()) {
            os << ms.count() << "ms" << (us.count() ? " " : "");
        }
        if (us.count()) {
            os << us.count() << "μs";
        }
    }

    return os.str();
}
}  // namespace silkworm
