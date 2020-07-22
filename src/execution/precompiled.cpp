/*
   Copyright 2020 The Silkworm Authors

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

#include "precompiled.hpp"

#include <boost/endian/conversion.hpp>
#include <cstring>
#include <ethash/keccak.hpp>

#include "common/util.hpp"
#include "crypto/ecdsa.hpp"

namespace silkworm::precompiled {

uint64_t ecrec_gas(std::string_view, evmc_revision) noexcept { return 3'000; }

std::optional<std::string> ecrec_run(std::string_view input) noexcept {
  constexpr size_t kInputLen{128};
  std::string d{input};
  if (d.length() < kInputLen) {
    d.resize(kInputLen, '\0');
  }

  auto v{intx::be::unsafe::load<intx::uint256>(byte_ptr_cast(&d[32]))};
  auto r{intx::be::unsafe::load<intx::uint256>(byte_ptr_cast(&d[64]))};
  auto s{intx::be::unsafe::load<intx::uint256>(byte_ptr_cast(&d[96]))};

  v -= 27;

  if (!ecdsa::inputs_are_valid(v, r, s)) return "";

  std::optional<std::string> key{
      ecdsa::recover(d.substr(0, 32), d.substr(64, 64), static_cast<uint8_t>(v))};
  if (!key) return "";

  // Ignore the first byte of the public key
  ethash::hash256 hash{ethash::keccak256(byte_ptr_cast(key->data() + 1), key->length() - 1)};

  std::string out(32, '\0');
  std::memcpy(&out[12], &hash.bytes[12], 32 - 12);

  return out;
}

uint64_t sha256_gas(std::string_view input, evmc_revision) noexcept {
  return 60 + 12 * ((input.length() + 31) / 32);
}

std::optional<std::string> sha256_run(std::string_view) noexcept {
  // TODO[Frontier] implement
  return {};
}

uint64_t rip160_gas(std::string_view input, evmc_revision) noexcept {
  return 600 + 120 * ((input.length() + 31) / 32);
}

std::optional<std::string> rip160_run(std::string_view) noexcept {
  // TODO[Frontier] implement
  return {};
}

uint64_t id_gas(std::string_view input, evmc_revision) noexcept {
  return 15 + 3 * ((input.length() + 31) / 32);
}

std::optional<std::string> id_run(std::string_view input) noexcept { return std::string{input}; }

uint64_t expmod_gas(std::string_view, evmc_revision) noexcept {
  // TODO[Byzantium] implement
  return 0;
}

std::optional<std::string> expmod_run(std::string_view) noexcept {
  // TODO[Byzantium] implement
  return {};
}

uint64_t bn_add_gas(std::string_view, evmc_revision rev) noexcept {
  return rev >= EVMC_ISTANBUL ? 150 : 500;
}

std::optional<std::string> bn_add_run(std::string_view) noexcept {
  // TODO[Byzantium] implement
  return {};
}

uint64_t bn_mul_gas(std::string_view, evmc_revision rev) noexcept {
  return rev >= EVMC_ISTANBUL ? 6'000 : 40'000;
}

std::optional<std::string> bn_mul_run(std::string_view) noexcept {
  // TODO[Byzantium] implement
  return {};
}

uint64_t snarkv_gas(std::string_view input, evmc_revision rev) noexcept {
  uint64_t k{input.length() / 192};
  return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

std::optional<std::string> snarkv_run(std::string_view) noexcept {
  // TODO[Byzantium] implement
  return {};
}

uint64_t blake2_f_gas(std::string_view input, evmc_revision) noexcept {
  if (input.length() < 4) return 0;  // blake2_f_run will fail anyway
  return boost::endian::load_big_u32(byte_ptr_cast(input.data()));
}

std::optional<std::string> blake2_f_run(std::string_view) noexcept {
  // TODO[Istanbul] implement
  return {};
}
}  // namespace silkworm::precompiled
