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

#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm {

//! \brief Components implementing stop-ability should derive from this
class Stoppable {
  public:
    //! \brief Sets a stop request for instance;
    //! \return True if the stop request has been triggered otherwise false (i.e. was already stopping)
    virtual bool stop() {
        bool expected{false};
        return stopping_.compare_exchange_strong(expected, true);
    }

    //! \brief Whether a stop request has been issued
    bool is_stopping() { return stopping_.load() || SignalHandler::signalled(); }

    virtual ~Stoppable() = default;

  private:
    std::atomic_bool stopping_{false};
};

}  // namespace silkworm
