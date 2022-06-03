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
    if (start_time_ == TimePoint()) {
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
    using namespace std::chrono_literals;
    using days = std::chrono::duration<int, std::ratio<86400>>;

    std::ostringstream os;
    char fill = os.fill('0');

    if (duration >= 60s) {
        bool need_space{false};
        if (auto d = std::chrono::duration_cast<days>(duration); d.count()) {
            os << d.count() << "d";
            duration -= d;
            need_space = true;
        }
        if (auto h = std::chrono::duration_cast<std::chrono::hours>(duration); h.count()) {
            os << (need_space ? " " : "") << h.count() << "h";
            duration -= h;
            need_space = true;
        }
        if (auto m = std::chrono::duration_cast<std::chrono::minutes>(duration); m.count()) {
            os << (need_space ? " " : "") << m.count() << "m";
            duration -= m;
            need_space = true;
        }
        if (auto s = std::chrono::duration_cast<std::chrono::seconds>(duration); s.count()) {
            os << (need_space ? " " : "") << s.count() << "s";
        }
    } else {
        if (duration >= 1s) {
            auto s = std::chrono::duration_cast<std::chrono::seconds>(duration);
            duration -= s;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
            os << s.count();
            if (ms.count()) {
                os << "." << std::setw(3) << ms.count();
            }
            os << "s";
        } else if (duration >= 1ms) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
            duration -= ms;
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(duration);
            os << ms.count();
            if (us.count()) {
                os << "." << std::setw(3) << us.count();
            }
            os << "ms";
        } else if (duration >= 1us) {
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(duration);
            os << us.count() << "us";
        }
    }

    os.fill(fill);
    return os.str();
}
}  // namespace silkworm
