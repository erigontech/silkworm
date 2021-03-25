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

#ifndef SILKWORM_EXECUTION_PRECOMPILED_HPP_
#define SILKWORM_EXECUTION_PRECOMPILED_HPP_

#include <optional>

#include <evmc/evmc.h>

#include <silkworm/common/base.hpp>

// See Yellow Paper, Appendix E "Precompiled Contracts"
namespace silkworm::precompiled {

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

// https://eips.ethereum.org/EIPS/eip-2565
uint64_t expmod_gas(ByteView input, evmc_revision) noexcept;
// https://eips.ethereum.org/EIPS/eip-198
std::optional<Bytes> expmod_run(ByteView input) noexcept;

// https://eips.ethereum.org/EIPS/eip-196
uint64_t bn_add_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> bn_add_run(ByteView input) noexcept;

// https://eips.ethereum.org/EIPS/eip-196
uint64_t bn_mul_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> bn_mul_run(ByteView input) noexcept;

// https://eips.ethereum.org/EIPS/eip-197
uint64_t snarkv_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> snarkv_run(ByteView input) noexcept;

// https://eips.ethereum.org/EIPS/eip-152
uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept;
std::optional<Bytes> blake2_f_run(ByteView input) noexcept;

constexpr Contract kContracts[]{
    {ecrec_gas, ecrec_run},   {sha256_gas, sha256_run}, {rip160_gas, rip160_run},
    {id_gas, id_run},         {expmod_gas, expmod_run}, {bn_add_gas, bn_add_run},
    {bn_mul_gas, bn_mul_run}, {snarkv_gas, snarkv_run}, {blake2_f_gas, blake2_f_run},
};

constexpr size_t kNumOfFrontierContracts{4};
constexpr size_t kNumOfByzantiumContracts{8};
constexpr size_t kNumOfIstanbulContracts{9};

static_assert(std::size(kContracts) == kNumOfIstanbulContracts);

}  // namespace silkworm::precompiled

#endif  // SILKWORM_EXECUTION_PRECOMPILED_HPP_
