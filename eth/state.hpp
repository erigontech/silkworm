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

#ifndef SILKWORM_ETH_STATE_H_
#define SILKWORM_ETH_STATE_H_

#include "common.hpp"

namespace silkworm::eth {

// Intra-block state
class State {
 public:
  State(const State&) = delete;
  State& operator=(const State&) = delete;

  uint64_t GetNonce(AddressRef address);
};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_STATE_H_
