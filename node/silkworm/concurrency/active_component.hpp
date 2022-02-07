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

#ifndef SILKWORM_CONCURRENCY_ACTIVE_COMPONENT_HPP_
#define SILKWORM_CONCURRENCY_ACTIVE_COMPONENT_HPP_

#include <atomic>

#include <silkworm/concurrency/stoppable.hpp>

namespace silkworm {

/*
 * Abstract interface for active components
 * i.e. component that have an infinite loop and need a dedicated thread to run the loop (if the application
 * has also other things to do).
 * Here we prefer not to provide a thread facility and let the user provide one more suitable to the context,
 * so perhaps a better name is LongRunningComponent.
 */
class ActiveComponent : public Stoppable {
  public:
    virtual void execution_loop() = 0;
};

}  // namespace silkworm

#endif  // SILKWORM_CONCURRENCY_ACTIVE_COMPONENT_HPP_
