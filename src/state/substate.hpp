/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_STATE_SUBSTATE_H_
#define SILKWORM_STATE_SUBSTATE_H_

#include <stdint.h>

#include <vector>

#include "types/log.hpp"

namespace silkworm {

// See Section 6.1 "Substate" of the Yellow Paper.
class Substate {
 public:
  // TODO[Frontier] self-destructs
  std::vector<Log> logs;
  // TODO[Spurious Dragon] touched accounts
  uint64_t refund{0};

  void clear();
};
}  // namespace silkworm

#endif  // SILKWORM_STATE_SUBSTATE_H_
