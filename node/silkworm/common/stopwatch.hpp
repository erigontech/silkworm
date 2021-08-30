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

#pragma once
#ifndef SILKWORM_STOPWATCH_HPP_
#define SILKWORM_STOPWATCH_HPP_

#include <chrono>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace silkworm {

//! \brief StopWatch class mimics the behavior of a stopwatch to measure timings of operations
class StopWatch {
  public:
    typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
    typedef std::chrono::nanoseconds Duration;

    //! Constructor
    StopWatch() = default;
    ~StopWatch() = default;

    //! \brief Start the clock
    //! \return The TimePoint it was started
    TimePoint start() noexcept;

    //! \brief Fixes a lap time
    //! \return A std::pair<TimePoint,Duration> where Duration measures the interval between this TimePoint and the
    //! previous one which might be another lap or the start
    std::pair<TimePoint, Duration> lap() noexcept;

    //! \brief Computes the Duration between provided TimePoint and the TimePoint recorded at clock start
    //! \param [in] origin : The TimePoint we want to record the Duration to
    //! \return A Duration
    Duration since_start(const TimePoint& origin) noexcept;

    //! \brief Stops the clock
    //! \return The TimePoint it was stopped
    TimePoint stop() noexcept;

    //! \brief Reset all counters
    //! \remarks If the clock is ticking it is also stopped
    void reset() noexcept;

    //! Returns all the recorded laptimes
    //! \return A vector
    const std::vector<std::pair<TimePoint, Duration>>& laps() const { return laps_; }

    //! \brief Produces a string with a duration in a human readable format
    static std::string format(Duration duration);

    //! \brief Whether the clock is started
    explicit operator bool() const noexcept { return started_; }

  private:
    bool started_{false};                                 // Records started/stopped state
    TimePoint start_time_{};                              // Initial start time
    std::vector<std::pair<TimePoint, Duration>> laps_{};  // Collected laptimes
};

}  // namespace silkworm

#endif  // !SILKWORM_STOPWATCH_HPP_
