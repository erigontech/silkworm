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

#include "stopwatch.hpp"

namespace silkworm {

StopWatch::TimePoint StopWatch::start() noexcept {
    if (started_) {
        return start_time_;
    }
    
    started_ = true;
    if (start_time_ == TimePoint()) {
        start_time_ = std::chrono::high_resolution_clock::now();
    }
    if (laps_.size()) {
        auto& [t, d] = laps_.back();
        laps_.emplace_back(start_time_, std::chrono::duration_cast<Duration>(start_time_ - t));
    } else {
        laps_.emplace_back(start_time_, std::chrono::duration_cast<Duration>(start_time_ - start_time_));
    }
    return start_time_;
}

std::pair<StopWatch::TimePoint, StopWatch::Duration> StopWatch::lap() noexcept {
    if (!started_ || !laps_.size()) {
        return {};
    }
    const auto lap_time{std::chrono::high_resolution_clock::now()};
    const auto& [t, d] = laps_.back();
    laps_.emplace_back(lap_time, std::chrono::duration_cast<Duration>(lap_time - t));
    return laps_.back();
}

StopWatch::Duration StopWatch::since_start(const TimePoint& origin) noexcept {
    if (!started_) {
        return {};
    }
    return Duration(origin - start_time_);
}

StopWatch::TimePoint StopWatch::stop() noexcept {
    if (started_) {
        TimePoint res{lap().first};
        started_ = false;
        return res;
    }
    return {};
}

void StopWatch::reset() noexcept {
    stop();
    start_time_ = TimePoint();
    std::vector<std::pair<TimePoint, Duration>>().swap(laps_);
}

std::string StopWatch::format(Duration duration) {
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
        if (d.count()) {
            os << std::setw(2) << std::setfill('0');
        }
        os << h.count() << "h";
        if (m.count() || s.count()) {
            os << ":";
        }
    }
    if (m.count() || h.count()) {
        if (h.count()) {
            os << std::setw(2) << std::setfill('0');
        }
        os << m.count() << "m";
        if (h.count() || s.count()) {
            os << ":";
        }
    }
    if (s.count() || m.count() || h.count()) {
        if (h.count() || m.count()) {
            os << std::setw(2) << std::setfill('0');
        }
        os << s.count();
        if (ms.count()) {
            os << "." << std::setw(3) << std::setfill('0') << ms.count() << "s";
        }
    }

    if (!d.count() && !h.count() && !m.count() && !s.count()) {
        if (ms.count()) {
            os << ms.count();
            if (us.count()) {
                os << "." << std::setw(3) << std::setfill('0') << us.count();
            }
            os << "ms";
        }
        if (us.count() && !ms.count()) {
            os << std::setw(3) << std::setfill('0') << us.count() << "us";
        }
    }

    return os.str();
}
}  // namespace silkworm
