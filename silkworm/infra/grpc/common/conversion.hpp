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

#include <memory>
#include <string>
#include <string_view>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/interfaces/types/types.pb.h>

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

bool operator==(const H512& lhs, const H512& rhs);
bool operator==(const H256& lhs, const H256& rhs);
bool operator==(const H160& lhs, const H160& rhs);
bool operator==(const H128& lhs, const H128& rhs);

}  // namespace types

namespace silkworm::rpc {

// TODO (canepat) move sentry_type_casts here and unify
// TODO (canepat) sentry_type_casts: better function naming, smart helpers
// TODO (canepat) conversion: better module name and location

//! Convert internal gRPC H2048 type instance to std::string.
std::string string_from_H2048(const ::types::H2048& orig);

//! Convert internal gRPC H2048 type instance to Bytes.
Bytes bytes_from_H2048(const ::types::H2048& h2048);

//! Convert internal gRPC H1024 type instance to Bytes.
Bytes bytes_from_H1024(const ::types::H1024& h1024);

//! Convert internal gRPC H512 type instance to std::string.
std::string string_from_H512(const ::types::H512& orig);

Bytes bytes_from_H512(const ::types::H512& h512);

//! Convert internal gRPC H256 type instance to evmc::bytes32.
evmc::bytes32 bytes32_from_H256(const ::types::H256& orig);

//! Convert internal gRPC H256 type instance to intx::uint256.
intx::uint256 uint256_from_H256(const ::types::H256& orig);

//! Convert internal gRPC H256 type instance to Bytes.
Bytes bytes_from_H256(const ::types::H256& h256);

//! Convert internal gRPC H160 type instance to evmc::address.
evmc::address address_from_H160(const ::types::H160& orig);

//! Convert internal gRPC H128 type instance to Bytes.
Bytes bytes_from_H128(const ::types::H128& h128);

//! Convert std::string_view to internal gRPC H2048 type instance.
std::unique_ptr<::types::H2048> H2048_from_string(std::string_view orig);

//! Convert ByteView to internal gRPC H2048 type instance.
std::unique_ptr<::types::H2048> H2048_from_bytes(ByteView bytes);

//! Convert ByteView to internal gRPC H1024 type instance.
std::unique_ptr<::types::H1024> H1024_from_bytes(ByteView bytes);

//! Convert evmc::address to internal gRPC H512 type instance.
std::unique_ptr<::types::H512> H512_from_string(std::string_view orig);

//! Convert ByteView to internal gRPC H512 type instance.
std::unique_ptr<::types::H512> H512_from_bytes(ByteView bytes);

//! Convert evmc::bytes32 to internal gRPC H256 type instance.
std::unique_ptr<::types::H256> H256_from_bytes32(const evmc::bytes32& orig);

//! Convert intx::uint256 to internal gRPC H256 type instance.
std::unique_ptr<::types::H256> H256_from_uint256(const intx::uint256& orig);

//! Convert ByteView to internal gRPC H256 type instance.
std::unique_ptr<::types::H256> H256_from_bytes(ByteView bytes);

//! Convert evmc::address to internal gRPC H160 type instance.
std::unique_ptr<::types::H160> H160_from_address(const evmc::address& orig);

//! Convert ByteView to internal gRPC H128 type instance.
std::unique_ptr<::types::H128> H128_from_bytes(ByteView bytes);

}  // namespace silkworm::rpc
