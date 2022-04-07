/*
   Copyright 2020-2022 The Silkworm Authors

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

#include <stddef.h>
#include <stdint.h>

#include <array>

#include <evmc/evmc.h>

// See Yellow Paper, Appendix E "Precompiled Contracts"

#define SILKPRE_NUMBER_OF_FRONTIER_CONTRACTS 4
#define SILKPRE_NUMBER_OF_BYZANTIUM_CONTRACTS 8
#define SILKPRE_NUMBER_OF_ISTANBUL_CONTRACTS 9

struct SilkpreOutput {
    uint8_t* data;  // Has to be freed if not NULL!!!
    size_t size;
};

using SilkpreGasFunction = uint64_t (*)(const uint8_t* input, size_t len, evmc_revision) noexcept;
using SilkpreRunFunction = SilkpreOutput (*)(const uint8_t* input, size_t len) noexcept;

struct SilkpreContract {
    SilkpreGasFunction gas;
    SilkpreRunFunction run;
};

uint64_t silkpre_ecrec_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_ecrec_run(const uint8_t* input, size_t len) noexcept;

uint64_t silkpre_sha256_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_sha256_run(const uint8_t* input, size_t len) noexcept;

uint64_t silkpre_rip160_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_rip160_run(const uint8_t* input, size_t len) noexcept;

uint64_t silkpre_id_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_id_run(const uint8_t* input, size_t len) noexcept;

// https://eips.ethereum.org/EIPS/eip-2565
uint64_t silkpre_expmod_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
// https://eips.ethereum.org/EIPS/eip-198
SilkpreOutput silkpre_expmod_run(const uint8_t* input, size_t len) noexcept;

// https://eips.ethereum.org/EIPS/eip-196
uint64_t silkpre_bn_add_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_bn_add_run(const uint8_t* input, size_t len) noexcept;

// https://eips.ethereum.org/EIPS/eip-196
uint64_t silkpre_bn_mul_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_bn_mul_run(const uint8_t* input, size_t len) noexcept;

// https://eips.ethereum.org/EIPS/eip-197
uint64_t silkpre_snarkv_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_snarkv_run(const uint8_t* input, size_t len) noexcept;

// https://eips.ethereum.org/EIPS/eip-152
uint64_t silkpre_blake2_f_gas(const uint8_t* input, size_t len, evmc_revision) noexcept;
SilkpreOutput silkpre_blake2_f_run(const uint8_t* input, size_t len) noexcept;

inline constexpr SilkpreContract kSilkpreContracts[]{
    {silkpre_ecrec_gas, silkpre_ecrec_run},       {silkpre_sha256_gas, silkpre_sha256_run},
    {silkpre_rip160_gas, silkpre_rip160_run},     {silkpre_id_gas, silkpre_id_run},
    {silkpre_expmod_gas, silkpre_expmod_run},     {silkpre_bn_add_gas, silkpre_bn_add_run},
    {silkpre_bn_mul_gas, silkpre_bn_mul_run},     {silkpre_snarkv_gas, silkpre_snarkv_run},
    {silkpre_blake2_f_gas, silkpre_blake2_f_run},
};

static_assert(std::size(kSilkpreContracts) == SILKPRE_NUMBER_OF_ISTANBUL_CONTRACTS);

#endif  // SILKWORM_EXECUTION_PRECOMPILED_HPP_
