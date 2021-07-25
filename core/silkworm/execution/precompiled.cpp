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

#include "precompiled.hpp"

#include <gmp.h>

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>

#include <ethash/keccak.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#pragma GCC diagnostic pop

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/blake2.h>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/crypto/rmd160.hpp>
#include <silkworm/crypto/sha-256.h>
#include <silkworm/crypto/snark.hpp>

namespace silkworm::precompiled {

uint64_t ecrec_gas(ByteView, evmc_revision) noexcept { return 3'000; }

std::optional<Bytes> ecrec_run(ByteView input) noexcept {
    static constexpr size_t kInputLen{128};
    Bytes d{input};
    if (d.length() < kInputLen) {
        d.resize(kInputLen, '\0');
    }

    auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    bool homestead{false};  // See EIP-2
    if (!ecdsa::is_valid_signature(r, s, homestead)) {
        return Bytes{};
    }

    ecdsa::YParityAndChainId y{ecdsa::v_to_y_parity_and_chain_id(v)};
    if (y.chain_id) {
        return Bytes{};
    }

    std::optional<Bytes> key{ecdsa::recover(d.substr(0, 32), d.substr(64, 64), y.odd)};
    if (!key || key->at(0) != 4) {
        return Bytes{};
    }

    // Ignore the first byte of the public key
    ethash::hash256 hash{ethash::keccak256(key->data() + 1, key->length() - 1)};

    Bytes out(32, '\0');
    std::memcpy(&out[12], &hash.bytes[12], 32 - 12);
    return out;
}

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept { return 60 + 12 * ((input.length() + 31) / 32); }

std::optional<Bytes> sha256_run(ByteView input) noexcept {
    Bytes out(32, '\0');
    calc_sha_256(out.data(), input.data(), input.length(), /*use_cpu_extensions=*/true);
    return out;
}

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept { return 600 + 120 * ((input.length() + 31) / 32); }

std::optional<Bytes> rip160_run(ByteView input) noexcept {
    Bytes out(32, '\0');
    crypto::calculate_ripemd_160(gsl::span<uint8_t, 20>{&out[12], 20}, input);
    return out;
}

uint64_t id_gas(ByteView input, evmc_revision) noexcept { return 15 + 3 * ((input.length() + 31) / 32); }

std::optional<Bytes> id_run(ByteView input) noexcept { return Bytes{input}; }

static intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept {
    const intx::uint256 x_squared{x * x};
    if (x <= 64) {
        return x_squared;
    } else if (x <= 1024) {
        return (x_squared >> 2) + 96 * x - 3072;
    } else {
        return (x_squared >> 4) + 480 * x - 199680;
    }
}

static intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept {
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

uint64_t expmod_gas(ByteView input, evmc_revision rev) noexcept {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};

    Bytes buffer;
    input = right_pad(input, 3 * 32, buffer);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0) {
        return min_gas;
    }

    if (intx::count_significant_words(base_len256) > 1 || intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1) {
        return UINT64_MAX;
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.remove_prefix(3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64) {
        ByteView exp_input{right_pad(input.substr(base_len64), 32, buffer)};
        if (exp_len64 < 32) {
            exp_input = exp_input.substr(0, exp_len64);
            exp_input = left_pad(exp_input, 32, buffer);
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(exp_input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32) {
        adjusted_exponent_len = 8 * (exp_len256 - 32);
    }
    if (bit_len > 1) {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1) {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN) {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / param::kGQuadDivisorByzantium;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / param::kGQuadDivisorBerlin;
    }

    if (intx::count_significant_words(gas) > 1) {
        return UINT64_MAX;
    } else {
        return std::max(min_gas, static_cast<uint64_t>(gas));
    }
}

std::optional<Bytes> expmod_run(ByteView input) noexcept {
    Bytes buffer;
    input = right_pad(input, 3 * 32, buffer);

    uint64_t base_len{endian::load_big_u64(&input[24])};
    input.remove_prefix(32);

    uint64_t exponent_len{endian::load_big_u64(&input[24])};
    input.remove_prefix(32);

    uint64_t modulus_len{endian::load_big_u64(&input[24])};
    input.remove_prefix(32);

    if (modulus_len == 0) {
        return Bytes{};
    }

    input = right_pad(input, base_len + exponent_len + modulus_len, buffer);

    mpz_t base;
    mpz_init(base);
    if (base_len) {
        mpz_import(base, base_len, 1, 1, 0, 0, input.data());
        input.remove_prefix(base_len);
    }

    mpz_t exponent;
    mpz_init(exponent);
    if (exponent_len) {
        mpz_import(exponent, exponent_len, 1, 1, 0, 0, input.data());
        input.remove_prefix(exponent_len);
    }

    mpz_t modulus;
    mpz_init(modulus);
    if (modulus_len) {
        mpz_import(modulus, modulus_len, 1, 1, 0, 0, input.data());
    }

    if (mpz_sgn(modulus) == 0) {
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return Bytes(modulus_len, '\0');
    }

    mpz_t result;
    mpz_init(result);

    mpz_powm(result, base, exponent, modulus);

    Bytes out(modulus_len, '\0');
    // export as little-endian
    mpz_export(out.data(), nullptr, -1, 1, 0, 0, result);
    // and convert to big-endian
    std::reverse(out.begin(), out.end());

    mpz_clear(result);
    mpz_clear(modulus);
    mpz_clear(exponent);
    mpz_clear(base);

    return out;
}

uint64_t bn_add_gas(ByteView, evmc_revision rev) noexcept { return rev >= EVMC_ISTANBUL ? 150 : 500; }

std::optional<Bytes> bn_add_run(ByteView input) noexcept {
    Bytes buffer;
    input = right_pad(input, 128, buffer);

    snark::init_libff();

    std::optional<libff::alt_bn128_G1> x{snark::decode_g1_element(input.substr(0, 64))};
    if (!x) {
        return std::nullopt;
    }

    std::optional<libff::alt_bn128_G1> y{snark::decode_g1_element(input.substr(64, 64))};
    if (!y) {
        return std::nullopt;
    }

    libff::alt_bn128_G1 sum{*x + *y};
    return snark::encode_g1_element(sum);
}

uint64_t bn_mul_gas(ByteView, evmc_revision rev) noexcept { return rev >= EVMC_ISTANBUL ? 6'000 : 40'000; }

std::optional<Bytes> bn_mul_run(ByteView input) noexcept {
    Bytes buffer;
    input = right_pad(input, 96, buffer);

    snark::init_libff();

    std::optional<libff::alt_bn128_G1> x{snark::decode_g1_element(input.substr(0, 64))};
    if (!x) {
        return std::nullopt;
    }

    snark::Scalar n{snark::to_scalar(input.substr(64, 32))};

    libff::alt_bn128_G1 product{n * *x};
    return snark::encode_g1_element(product);
}

constexpr size_t kSnarkvStride{192};

uint64_t snarkv_gas(ByteView input, evmc_revision rev) noexcept {
    uint64_t k{input.length() / kSnarkvStride};
    return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

std::optional<Bytes> snarkv_run(ByteView input) noexcept {
    if (input.size() % kSnarkvStride != 0) {
        return std::nullopt;
    }
    size_t k{input.size() / kSnarkvStride};

    snark::init_libff();
    using namespace libff;

    static const auto one{alt_bn128_Fq12::one()};
    auto accumulator{one};

    for (size_t i{0}; i < k; ++i) {
        std::optional<alt_bn128_G1> a{snark::decode_g1_element(input.substr(i * kSnarkvStride, 64))};
        if (!a) {
            return std::nullopt;
        }
        std::optional<alt_bn128_G2> b{snark::decode_g2_element(input.substr(i * kSnarkvStride + 64, 128))};
        if (!b) {
            return std::nullopt;
        }

        if (a->is_zero() || b->is_zero()) {
            continue;
        }

        accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(*a), alt_bn128_precompute_G2(*b));
    }

    Bytes out(32, '\0');
    if (alt_bn128_final_exponentiation(accumulator) == one) {
        out[31] = 1;
    }
    return out;
}

uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept {
    if (input.length() < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return endian::load_big_u32(input.data());
}

std::optional<Bytes> blake2_f_run(ByteView input) noexcept {
    if (input.size() != 213) {
        return std::nullopt;
    }
    uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return std::nullopt;
    }

    blake2b_state state{};
    if (f) {
        state.f[0] = std::numeric_limits<uint64_t>::max();
    }

    static_assert(SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN);
    static_assert(sizeof(state.h) == 8 * 8);
    std::memcpy(&state.h, input.data() + 4, 8 * 8);

    uint8_t block[BLAKE2B_BLOCKBYTES];
    std::memcpy(block, input.data() + 68, BLAKE2B_BLOCKBYTES);

    std::memcpy(&state.t, input.data() + 196, 8 * 2);

    uint32_t r{endian::load_big_u32(input.data())};
    blake2b_compress(&state, block, r);

    Bytes out(8 * 8, '\0');
    std::memcpy(&out[0], &state.h[0], 8 * 8);
    return out;
}

}  // namespace silkworm::precompiled
