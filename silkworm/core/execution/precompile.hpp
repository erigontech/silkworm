// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>

// See Yellow Paper, Appendix E "Precompiled Contracts"
namespace silkworm::precompile {

using GasFunction = uint64_t (*)(ByteView input, evmc_revision) noexcept;
using RunFunction = std::optional<Bytes> (*)(ByteView input) noexcept;

struct Contract {
    GasFunction gas;
    RunFunction run;
};

uint64_t ecrec_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> ecrec_run(ByteView input) noexcept;

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> sha256_run(ByteView input) noexcept;

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> rip160_run(ByteView input) noexcept;

uint64_t id_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> id_run(ByteView input) noexcept;

// EIP-2565: ModExp Gas Cos
uint64_t expmod_gas(ByteView input, evmc_revision) noexcept;
// EIP-198: Big integer modular exponentiation
std::optional<Bytes> expmod_run(ByteView input) noexcept;

// EIP-196: Precompiled contracts for addition and scalar multiplication on the elliptic curve alt_bn128
uint64_t bn_add_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> bn_add_run(ByteView input) noexcept;

// EIP-196: Precompiled contracts for addition and scalar multiplication on the elliptic curve alt_bn128
uint64_t bn_mul_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> bn_mul_run(ByteView input) noexcept;

// EIP-197: Precompiled contracts for optimal ate pairing check on the elliptic curve alt_bn128
uint64_t snarkv_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> snarkv_run(ByteView input) noexcept;

// EIP-152: Add BLAKE2 compression function `F` precompile
uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> blake2_f_run(ByteView input) noexcept;

// EIP-4844: Shard Blob Transactions
uint64_t point_evaluation_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> point_evaluation_run(ByteView input) noexcept;

struct SupportedContract {
    Contract contract;
    evmc_revision added_in;
};

inline constexpr std::optional<SupportedContract> kContracts[]{
    std::nullopt,                                                                  // 0x00
    SupportedContract{{ecrec_gas, ecrec_run}, EVMC_FRONTIER},                      // 0x01
    SupportedContract{{sha256_gas, sha256_run}, EVMC_FRONTIER},                    // 0x02
    SupportedContract{{rip160_gas, rip160_run}, EVMC_FRONTIER},                    // 0x03
    SupportedContract{{id_gas, id_run}, EVMC_FRONTIER},                            // 0x04
    SupportedContract{{expmod_gas, expmod_run}, EVMC_BYZANTIUM},                   // 0x05
    SupportedContract{{bn_add_gas, bn_add_run}, EVMC_BYZANTIUM},                   // 0x06
    SupportedContract{{bn_mul_gas, bn_mul_run}, EVMC_BYZANTIUM},                   // 0x07
    SupportedContract{{snarkv_gas, snarkv_run}, EVMC_BYZANTIUM},                   // 0x08
    SupportedContract{{blake2_f_gas, blake2_f_run}, EVMC_ISTANBUL},                // 0x09
    SupportedContract{{point_evaluation_gas, point_evaluation_run}, EVMC_CANCUN},  // 0x0a
};

bool is_precompile(const evmc::address&, evmc_revision) noexcept;

}  // namespace silkworm::precompile
