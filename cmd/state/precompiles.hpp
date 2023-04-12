// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>
#include <optional>
#include <type_traits>

namespace stdx
{
template <typename EnumT>
inline constexpr auto to_underlying(EnumT e) noexcept
{
    return static_cast<std::underlying_type_t<EnumT>>(e);
}
}  // namespace stdx

namespace silkworm::state
{
/// The total number of known precompiles ids, including 0.
inline constexpr std::size_t NumPrecompiles = 10;

enum class PrecompileId : uint8_t
{
    ecrecover = 0x01,
    sha256 = 0x02,
    ripemd160 = 0x03,
    identity = 0x04,
    expmod = 0x05,
    ecadd = 0x06,
    ecmul = 0x07,
    ecpairing = 0x08,
    blake2bf = 0x09,
};

struct ExecutionResult
{
    evmc_status_code status_code;
    size_t output_size;
};

std::optional<evmc::Result> call_precompile(evmc_revision rev, const evmc_message& msg) noexcept;
}  // namespace silkworm::state
