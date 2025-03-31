// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/interfaces/types/types.pb.h>

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

bool operator==(const H2048& lhs, const H2048& rhs);
bool operator==(const H1024& lhs, const H1024& rhs);
bool operator==(const H512& lhs, const H512& rhs);
bool operator==(const H256& lhs, const H256& rhs);
bool operator==(const H160& lhs, const H160& rhs);
bool operator==(const H128& lhs, const H128& rhs);

}  // namespace types

namespace silkworm::rpc {

//! Convert internal gRPC H2048 type instance to std::string.
std::string string_from_h2048(const ::types::H2048& orig);

//! Convert internal gRPC H2048 type instance to Bytes.
Bytes bytes_from_h2048(const ::types::H2048& h2048);

//! Convert internal gRPC H2048 type instance into provided fixed-size ByteSpan.
void span_from_h2048(const ::types::H2048& h2048, ByteSpan<256> bytes);

//! Convert internal gRPC H1024 type instance to Bytes.
Bytes bytes_from_h1024(const ::types::H1024& h1024);

//! Convert internal gRPC H1024 type instance into provided fixed-size ByteSpan.
void span_from_h1024(const ::types::H1024& h1024, ByteSpan<128> bytes);

//! Convert internal gRPC H512 type instance to std::string.
std::string string_from_h512(const ::types::H512& orig);

//! Convert internal gRPC H512 type instance to Bytes.
Bytes bytes_from_h512(const ::types::H512& h512);

//! Convert internal gRPC H512 type instance into provided fixed-size ByteSpan.
void span_from_h512(const ::types::H512& h512, ByteSpan<64> bytes);

//! Convert internal gRPC H256 type instance to evmc::bytes32.
evmc::bytes32 bytes32_from_h256(const ::types::H256& orig);

//! Convert internal gRPC H256 type instance to intx::uint256.
intx::uint256 uint256_from_h256(const ::types::H256& orig);

//! Convert internal gRPC H256 type instance to Bytes.
Bytes bytes_from_h256(const ::types::H256& h256);

//! Convert internal gRPC H256 type instance into provided fixed-size ByteSpan.
void span_from_h256(const ::types::H256& h256, ByteSpan<32> bytes);

//! Convert internal gRPC H160 type instance to evmc::address.
evmc::address address_from_h160(const ::types::H160& orig);

//! Convert internal gRPC H128 type instance to Bytes.
Bytes bytes_from_h128(const ::types::H128& h128);

//! Convert internal gRPC H128 type instance into provided fixed-size ByteSpan.
void span_from_h128(const ::types::H128& h128, ByteSpan<16> bytes);

//! Convert std::string_view to internal gRPC H2048 type instance.
std::unique_ptr<::types::H2048> h2048_from_string(std::string_view orig);

//! Convert ByteView to internal gRPC H2048 type instance.
std::unique_ptr<::types::H2048> h2048_from_bytes(ByteView bytes);

//! Convert ByteView to internal gRPC H1024 type instance.
std::unique_ptr<::types::H1024> h1024_from_bytes(ByteView bytes);

//! Convert evmc::address to internal gRPC H512 type instance.
std::unique_ptr<::types::H512> h512_from_string(std::string_view orig);

//! Convert ByteView to internal gRPC H512 type instance.
std::unique_ptr<::types::H512> h512_from_bytes(ByteView bytes);

//! Convert evmc::bytes32 to internal gRPC H256 type instance.
void h256_from_bytes32(const evmc::bytes32& orig, ::types::H256* dest);

//! Convert evmc::bytes32 to internal gRPC H256 type instance.
std::unique_ptr<::types::H256> h256_from_bytes32(const evmc::bytes32& orig);

//! Convert intx::uint256 to internal gRPC H256 type instance.
std::unique_ptr<::types::H256> h256_from_uint256(const intx::uint256& orig);

//! Convert ByteView to internal gRPC H256 type instance.
std::unique_ptr<::types::H256> h256_from_bytes(ByteView bytes);

//! Convert evmc::address to internal gRPC H160 type instance.
std::unique_ptr<::types::H160> h160_from_address(const evmc::address& orig);

//! Convert ByteView to internal gRPC H128 type instance.
std::unique_ptr<::types::H128> h128_from_bytes(ByteView bytes);

}  // namespace silkworm::rpc
