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

#ifndef SILKWORM_RPC_CONVERSION_HPP_
#define SILKWORM_RPC_CONVERSION_HPP_

#include <string>

#include <evmc/evmc.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/endian.hpp>
#include <types/types.pb.h>

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

bool operator==(const H512& lhs, const H512& rhs);
bool operator==(const H256& lhs, const H256& rhs);
bool operator==(const H160& lhs, const H160& rhs);
bool operator==(const H128& lhs, const H128& rhs);

} // namespace types

namespace silkworm::rpc {

//! Convert internal RPC H512 type instance to std::string.
std::string string_from_H512(const types::H512& orig);

//! Convert internal RPC H256 type instance to evmc::bytes32.
evmc::bytes32 bytes32_from_H256(const types::H256& orig);

//! Convert internal RPC H160 type instance to evmc::address.
evmc::address address_from_H160(const types::H160& orig);

//! Convert evmc::address to internal RPC H160 type instance.
types::H512* new_H512_from_string(const std::string& orig);

//! Convert evmc::bytes32 to internal RPC H256 type instance.
types::H256* new_H256_from_bytes32(const evmc::bytes32& orig);

//! Convert evmc::address to internal RPC H160 type instance.
types::H160* new_H160_from_address(const evmc::address& orig);

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_CONVERSION_HPP_
