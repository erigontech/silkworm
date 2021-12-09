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
#ifndef SILKWORM_COMMON_STOPWATCH_HPP_
#define SILKWORM_COMMON_STOPWATCH_HPP_

#include <chrono>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace silkworm {
//! \brief This class mimics the behavior of a stopwatch to measure timings of operations
class StopWatch {
  public:
    typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
    typedef std::chrono::nanoseconds Duration;

    //! \brief Creates a new instance
    StopWatch() = default;
    ~StopWatch() = default;

    //! \brief Starts the clock
    //! \return The TimePoint it was started on
    TimePoint start(bool with_reset = false) noexcept;

    //! \brief Records a lap time
    //! \return A pair of TimePoint and Duration
    std::pair<TimePoint, Duration> lap() noexcept;

    //! \brief Computes the duration amongst the start time and the provided timepoint
    //! \param origin [in] : An origin timepoint
    //! \return  Duration
    Duration since_start(const TimePoint& origin) noexcept;

    //! \brief Stops the watch
    //! \return The timepoint of stop
    TimePoint stop() noexcept;

    //! \brief Stops the watch and clears all counters
    void reset() noexcept;

    //! \brief Returns the vector of laptimes
    [[nodiscard]] const std::vector<std::pair<TimePoint, Duration>>& laps() const { return laps_; }

    //! \brief Returns a human readable duration
    static std::string format(Duration duration) noexcept;

    explicit operator bool() const noexcept { return started_; }

  private:
    bool started_{false};
    TimePoint start_time_{};
    std::vector<std::pair<TimePoint, Duration>> laps_{};
};

}  // namespace silkworm

#endif  // !SILKWORM_COMMON_STOPWATCH_HPP_
