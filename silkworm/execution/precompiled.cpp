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

#include <cryptopp/ripemd.h>
#include <cryptopp/sha.h>

#include <boost/endian/conversion.hpp>
#include <cstring>
#include <ethash/keccak.hpp>
#include <iostream>  // TODO[Byzantium] remove
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/crypto/snark.hpp>

namespace silkworm::precompiled {

uint64_t ecrec_gas(ByteView, evmc_revision) noexcept { return 3'000; }

std::optional<Bytes> ecrec_run(ByteView input) noexcept {
  constexpr size_t kInputLen{128};
  Bytes d{input};
  if (d.length() < kInputLen) {
    d.resize(kInputLen, '\0');
  }

  auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
  auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
  auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

  v -= 27;

  // https://eips.ethereum.org/EIPS/eip-2
  if (!ecdsa::inputs_are_valid(v, r, s, /*homestead=*/false)) {
    return Bytes{};
  }

  std::optional<Bytes> key{
      ecdsa::recover(d.substr(0, 32), d.substr(64, 64), intx::narrow_cast<uint8_t>(v))};
  if (!key) {
    return Bytes{};
  }

  // Ignore the first byte of the public key
  ethash::hash256 hash{ethash::keccak256(key->data() + 1, key->length() - 1)};

  Bytes out(32, '\0');
  std::memcpy(&out[12], &hash.bytes[12], 32 - 12);
  return out;
}

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept {
  return 60 + 12 * ((input.length() + 31) / 32);
}

std::optional<Bytes> sha256_run(ByteView input) noexcept {
  Bytes out(CryptoPP::SHA256::DIGESTSIZE, '\0');
  CryptoPP::SHA256 hash;
  hash.CalculateDigest(&out[0], input.data(), input.length());
  return out;
}

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept {
  return 600 + 120 * ((input.length() + 31) / 32);
}

std::optional<Bytes> rip160_run(ByteView input) noexcept {
  Bytes out(32, '\0');
  CryptoPP::RIPEMD160 hash;
  hash.CalculateDigest(&out[12], input.data(), input.length());
  return out;
}

uint64_t id_gas(ByteView input, evmc_revision) noexcept {
  return 15 + 3 * ((input.length() + 31) / 32);
}

std::optional<Bytes> id_run(ByteView input) noexcept { return Bytes{input}; }

uint64_t expmod_gas(ByteView, evmc_revision) noexcept {
  std::cerr << "[Byzantium] expmod_gas!!!\n";
  // TODO[Byzantium] implement
  return 0;
}

std::optional<Bytes> expmod_run(ByteView) noexcept {
  std::cerr << "[Byzantium] expmod_run!!!\n";
  // TODO[Byzantium] implement
  return {};
}

uint64_t bn_add_gas(ByteView, evmc_revision rev) noexcept {
  return rev >= EVMC_ISTANBUL ? 150 : 500;
}

std::optional<Bytes> bn_add_run(ByteView input) noexcept {
  input = right_pad(input, 128);

  std::optional<libff::alt_bn128_G1> x{snark::decode_g1_element(input.substr(0, 64))};
  if (!x) {
    return {};
  }

  std::optional<libff::alt_bn128_G1> y{snark::decode_g1_element(input.substr(64, 64))};
  if (!y) {
    return {};
  }

  libff::alt_bn128_G1 sum{*x + *y};
  return snark::encode_g1_element(sum);
}

uint64_t bn_mul_gas(ByteView, evmc_revision rev) noexcept {
  return rev >= EVMC_ISTANBUL ? 6'000 : 40'000;
}

std::optional<Bytes> bn_mul_run(ByteView input) noexcept {
  input = right_pad(input, 96);

  std::optional<libff::alt_bn128_G1> x{snark::decode_g1_element(input.substr(0, 64))};
  if (!x) {
    return {};
  }

  auto n{snark::to_bigint(input.substr(64, 32))};

  libff::alt_bn128_G1 product{n * *x};
  return snark::encode_g1_element(product);
}

uint64_t snarkv_gas(ByteView input, evmc_revision rev) noexcept {
  uint64_t k{input.length() / 192};
  return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

std::optional<Bytes> snarkv_run(ByteView) noexcept {
  std::cerr << "[Byzantium] snarkv_run!!!\n";
  // TODO[Byzantium] implement
  return {};
}

uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept {
  if (input.length() < 4) {
    // blake2_f_run will fail anyway
    return 0;
  }
  return boost::endian::load_big_u32(input.data());
}

std::optional<Bytes> blake2_f_run(ByteView) noexcept {
  // TODO[Istanbul] implement
  return {};
}
}  // namespace silkworm::precompiled
