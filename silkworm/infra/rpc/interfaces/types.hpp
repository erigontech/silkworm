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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/interfaces/types/types.pb.h>

namespace silkworm {

Bytes bytes_from_H512(const types::H512& orig);
std::unique_ptr<types::H512> H512_from_bytes(ByteView orig);

Hash hash_from_H256(const types::H256& orig);
std::unique_ptr<types::H256> H256_from_hash(const Hash& orig);

intx::uint256 uint256_from_H256(const types::H256& orig);
std::unique_ptr<types::H256> H256_from_uint256(const intx::uint256& orig);

}  // namespace silkworm
