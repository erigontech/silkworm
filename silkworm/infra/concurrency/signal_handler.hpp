/*
   Copyright 2022 The Silkworm Authors

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

#include <atomic>
#include <cstdint>
#include <functional>

namespace silkworm {

//! \brief Handler for system signals using static storage
class SignalHandler {
  public:
    //! Register its own signal handling hook (previous handlers are saved)
    static void init(std::function<void(int)> custom_handler = {}, bool silent = false);

    //! Handle incoming signal
    static void handle(int sig_code);

    //! Whether any signal has been intercepted or not
    static bool signalled() { return signalled_; }

    //! Reset to un-signalled state (restore previous signal handlers)
    static void reset();

    //! Throw std::runtime_error if in signalled state
    static void throw_if_signalled();

  private:
    //! Last signal code which raised the signalled state
    static std::atomic_int sig_code_;

    //! Number of signals intercepted
    static std::atomic_uint32_t sig_count_;

    //! Whether a signal has been intercepted
    static std::atomic_bool signalled_;

    //! Custom handling
    static std::function<void(int)> custom_handler_;

    //! Flag indicating if signal handler can write on standard streams or not
    static bool silent_;
};

}  // namespace silkworm
