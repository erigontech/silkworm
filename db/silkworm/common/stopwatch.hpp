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
#include <optional>

#include <iostream>
#include <sstream>
#include <string>

#include <utility>
#include <vector>
#include <iomanip>

namespace silkworm {
/// <summary>
/// This class mimimcs the behavior of a stopwatch to measure timings of operations
/// </summary>
class StopWatch {
  public:
    typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
    typedef std::chrono::nanoseconds Duration;

    /// <summary>
    /// Creates a new instance
    /// </summary>
    StopWatch() = default;
    ~StopWatch() = default;

    /// <summary>
    /// Starts the clock
    /// </summary>
    /// <returns>The TimePoint it was started on</returns>
    TimePoint start() noexcept;

    /// <summary>
    /// Records a lap time
    /// </summary>
    /// <returns>A pair of TimePoint and Duration</returns>
    std::pair<TimePoint, Duration> lap() noexcept;

    /// <summary>
    /// Computes the duration amongst the start time and the
    /// provided timepoint
    /// </summary>
    /// <param name="origin">An origin timepoint</param>
    /// <returns>A Duration</returns>
    Duration since_start(const TimePoint& origin) noexcept;

    /// <summary>
    /// Stops the watch
    /// </summary>
    TimePoint stop() noexcept;

    /// <summary>
    /// Stops the watch and clears all counters
    /// </summary>
    void reset() noexcept;

    /// <summary>
    /// Returns the vector of laptimes
    /// </summary>
    const std::vector<std::pair<TimePoint, Duration>>& laps() const { return laps_; }

    /// <summary>
    /// Returns a human readable duration
    /// </summary>
    static std::string format(Duration duration);

    explicit operator bool() const noexcept { return started_; }

  private:
    bool started_{false};
    TimePoint start_time_{};
    std::vector<std::pair<TimePoint, Duration>> laps_{};
};


}  // namespace silkworm
#endif  // !SILKWORM_STOPWATCH_HPP_
