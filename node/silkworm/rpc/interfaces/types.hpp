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

#include <intx/intx.hpp>
#include <types/types.pb.h>

#include <silkworm/common/base.hpp>
#include <silkworm/types/hash.hpp>

namespace silkworm {

std::unique_ptr<types::H512> to_H512(const Bytes& orig);
Bytes bytes_from_H512(const types::H512& orig);

Hash hash_from_H256(const types::H256& orig);
intx::uint256 uint256_from_H256(const types::H256& orig);

}  // namespace silkworm
