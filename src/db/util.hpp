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

#ifndef SILKWORM_DB_UTIL_H_
#define SILKWORM_DB_UTIL_H_

#include <stdint.h>

#include <evmc/evmc.hpp>
#include <string>

namespace silkworm::db {
std::string storage_key(const evmc::address& address, uint64_t incarnation,
                        const evmc::bytes32& key);
}

#endif  // SILKWORM_DB_UTIL_H_
