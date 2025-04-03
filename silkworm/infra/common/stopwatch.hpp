// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

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
    using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;
    using Duration = std::chrono::nanoseconds;

    static constexpr bool kStart = true;

    //! \brief Creates a new instance
    explicit StopWatch(bool auto_start = false) {
        if (auto_start) start();
    };
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

    //! \brief Computes the duration amongst now and the start time
    //! \return  Duration
    Duration since_start() noexcept;

    //! \brief Stops the watch
    //! \return The timepoint of stop and the duration since start (if no laptimes) or the duration from previous
    //! laptime
    std::pair<TimePoint, Duration> stop() noexcept;

    //! \brief Stops the watch and clears all counters
    void reset() noexcept;

    //! \brief Returns the vector of laptimes
    const std::vector<std::pair<TimePoint, Duration>>& laps() const { return laps_; }

    //! \brief Returns a human readable duration
    static std::string format(Duration duration) noexcept;

    explicit operator bool() const noexcept { return started_; }

  private:
    bool started_{false};
    TimePoint start_time_{};
    std::vector<std::pair<TimePoint, Duration>> laps_{};
};

}  // namespace silkworm
