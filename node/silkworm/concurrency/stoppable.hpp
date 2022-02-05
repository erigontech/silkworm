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

#ifndef SILKWORM_CONCURRENCY_STOPPABLE_HPP_
#define SILKWORM_CONCURRENCY_STOPPABLE_HPP_

#include <atomic>

namespace silkworm {

//! \brief Components implementing stoppability should derive from this
class Stoppable {
  public:
    //! \brief Sets a stop request for instance;
    //! \return True if the stop request has been triggered otherwise false (i.e. was already stopping)
    virtual bool stop() {
        bool expected{false};
        return stopping_.compare_exchange_strong(expected, true);
    }

    //! \brief Whether a stop request has been issued
    [[nodiscard]] bool is_stopping() { return stopping_.load(); }

    virtual ~Stoppable() = default;

  private:
    std::atomic_bool stopping_{false};
};

}  // namespace silkworm
#endif  // SILKWORM_CONCURRENCY_STOPPABLE_HPP_
