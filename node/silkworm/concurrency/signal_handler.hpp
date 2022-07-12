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

#pragma once
#ifndef SILKWORM_CONCURRENCY_SIGNAL_HANDLER_HPP_
#define SILKWORM_CONCURRENCY_SIGNAL_HANDLER_HPP_

#include <atomic>
#include <cstdint>

namespace silkworm {

//! \brief Handler with static storage for signals sig
class SignalHandler {
  public:
    static void init();                                           // Enable the hooks
    static void handle(int sig_code);                             // Handles incoming signal
    [[nodiscard]] static bool signalled() { return signalled_; }  // Whether a signal has been intercepted
    static void reset();                                          // Reset to un-signalled (see tests coverage)

  private:
    static std::atomic_uint32_t sig_count_;
    static std::atomic_bool signalled_;
};

}  // namespace silkworm

#endif  // SILKWORM_CONCURRENCY_SIGNAL_HANDLER_HPP_
