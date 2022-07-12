/*
   Copyright 2020-2021 The Silkworm Authors

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
#ifndef SILKWORM_CORE_CHAIN_GENESIS_HPP_
#define SILKWORM_CORE_CHAIN_GENESIS_HPP_

#include <string>
#include <cstddef>

namespace silkworm {

/*
* \brief Returns genesis data given a known chain_id.
* If id is not recognized returns an invalid json string
*/
std::string read_genesis_data(uint64_t chain_id);

}  // namespace silkworm

#endif  // SILKWORM_CORE_CHAIN_GENESIS_HPP_
