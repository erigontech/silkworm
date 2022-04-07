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

#include "precompiled.hpp"

#include <gmp.h>

#include <algorithm>
#include <cstring>
#include <limits>

#include <ethash/keccak.hpp>
#include <silkpre/blake2b.h>
#include <silkpre/ecdsa.h>
#include <silkpre/rmd160.h>
#include <silkpre/sha256.h>
#include <silkpre/snark.hpp>
#include <silkpre/y_parity_and_chain_id.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#pragma GCC diagnostic pop

#include <silkworm/common/endian.hpp>

namespace silkworm::precompiled {

static void right_pad(Bytes& str, const size_t min_size) {
    if (str.length() < min_size) {
        str.resize(min_size, '\0');
    }
}

uint64_t ecrec_gas(const uint8_t*, size_t, evmc_revision) noexcept { return 3'000; }

Output ecrec_run(const uint8_t* input, size_t len) noexcept {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};

    Bytes d(input, len);
    right_pad(d, 128);

    const auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    const auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    const auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    const bool homestead{false};  // See EIP-2
    if (!silkpre::is_valid_signature(r, s, homestead)) {
        return {out, 0};
    }

    const std::optional<silkpre::YParityAndChainId> parity_and_id{silkpre::v_to_y_parity_and_chain_id(v)};
    if (parity_and_id == std::nullopt || parity_and_id->chain_id != std::nullopt) {
        return {out, 0};
    }

    std::memset(out, 0, 12);
    static secp256k1_context* context{secp256k1_context_create(SILKPRE_SECP256K1_CONTEXT_FLAGS)};
    if (!silkpre_recover_address(out + 12, &d[0], &d[64], parity_and_id->odd, context)) {
        return {out, 0};
    }
    return {out, 32};
}

uint64_t sha256_gas(const uint8_t*, size_t len, evmc_revision) noexcept { return 60 + 12 * ((len + 31) / 32); }

Output sha256_run(const uint8_t* input, size_t len) noexcept {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    silkpre_sha256(out, input, len, /*use_cpu_extensions=*/true);
    return {out, 32};
}

uint64_t rip160_gas(const uint8_t*, size_t len, evmc_revision) noexcept { return 600 + 120 * ((len + 31) / 32); }

Output rip160_run(const uint8_t* input, size_t len) noexcept {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    std::memset(out, 0, 12);
    silkpre_rmd160(&out[12], input, len);
    return {out, 32};
}

uint64_t id_gas(const uint8_t*, size_t len, evmc_revision) noexcept { return 15 + 3 * ((len + 31) / 32); }

Output id_run(const uint8_t* input, size_t len) noexcept {
    uint8_t* out{static_cast<uint8_t*>(std::malloc(len))};
    std::memcpy(out, input, len);
    return {out, len};
}

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

uint64_t expmod_gas(const uint8_t* ptr, size_t len, evmc_revision rev) noexcept {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};

    Bytes input(ptr, len);
    right_pad(input, 3 * 32);

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

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64) {
        input.erase(0, base_len64);
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(exp_len64);
            input.insert(0, 32 - exp_len64, '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
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
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (intx::count_significant_words(gas) > 1) {
        return UINT64_MAX;
    } else {
        return std::max(min_gas, static_cast<uint64_t>(gas));
    }
}

Output expmod_run(const uint8_t* ptr, size_t len) noexcept {
    Bytes input(ptr, len);
    right_pad(input, 3 * 32);

    const uint64_t base_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    const uint64_t exponent_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    const uint64_t modulus_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    if (modulus_len == 0) {
        uint8_t* out{static_cast<uint8_t*>(std::malloc(1))};
        return {out, 0};
    }

    right_pad(input, base_len + exponent_len + modulus_len);

    mpz_t base;
    mpz_init(base);
    if (base_len) {
        mpz_import(base, base_len, 1, 1, 0, 0, input.data());
        input.erase(0, base_len);
    }

    mpz_t exponent;
    mpz_init(exponent);
    if (exponent_len) {
        mpz_import(exponent, exponent_len, 1, 1, 0, 0, input.data());
        input.erase(0, exponent_len);
    }

    mpz_t modulus;
    mpz_init(modulus);
    mpz_import(modulus, modulus_len, 1, 1, 0, 0, input.data());

    uint8_t* out{static_cast<uint8_t*>(std::malloc(modulus_len))};
    std::memset(out, 0, modulus_len);

    if (mpz_sgn(modulus) == 0) {
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return {out, static_cast<size_t>(modulus_len)};
    }

    mpz_t result;
    mpz_init(result);

    mpz_powm(result, base, exponent, modulus);

    // export as little-endian
    mpz_export(out, nullptr, -1, 1, 0, 0, result);
    // and convert to big-endian
    std::reverse(out, out + modulus_len);

    mpz_clear(result);
    mpz_clear(modulus);
    mpz_clear(exponent);
    mpz_clear(base);

    return {out, static_cast<size_t>(modulus_len)};
}

uint64_t bn_add_gas(const uint8_t*, size_t, evmc_revision rev) noexcept { return rev >= EVMC_ISTANBUL ? 150 : 500; }

Output bn_add_run(const uint8_t* ptr, size_t len) noexcept {
    Bytes input(ptr, len);
    right_pad(input, 128);

    silkpre::init_libff();

    std::optional<libff::alt_bn128_G1> x{silkpre::decode_g1_element(input.data())};
    if (!x) {
        return {nullptr, 0};
    }

    std::optional<libff::alt_bn128_G1> y{silkpre::decode_g1_element(&input[64])};
    if (!y) {
        return {nullptr, 0};
    }

    libff::alt_bn128_G1 sum{*x + *y};
    const std::basic_string<uint8_t> res{silkpre::encode_g1_element(sum)};

    uint8_t* out{static_cast<uint8_t*>(std::malloc(res.length()))};
    std::memcpy(out, res.data(), res.length());
    return {out, res.length()};
}

uint64_t bn_mul_gas(const uint8_t*, size_t, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 6'000 : 40'000;
}

Output bn_mul_run(const uint8_t* ptr, size_t len) noexcept {
    Bytes input(ptr, len);
    right_pad(input, 96);

    silkpre::init_libff();

    std::optional<libff::alt_bn128_G1> x{silkpre::decode_g1_element(input.data())};
    if (!x) {
        return {nullptr, 0};
    }

    silkpre::Scalar n{silkpre::to_scalar(&input[64])};

    libff::alt_bn128_G1 product{n * *x};
    const std::basic_string<uint8_t> res{silkpre::encode_g1_element(product)};

    uint8_t* out{static_cast<uint8_t*>(std::malloc(res.length()))};
    std::memcpy(out, res.data(), res.length());
    return {out, res.length()};
}

static constexpr size_t kSnarkvStride{192};

uint64_t snarkv_gas(const uint8_t*, size_t len, evmc_revision rev) noexcept {
    uint64_t k{len / kSnarkvStride};
    return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

Output snarkv_run(const uint8_t* input, size_t len) noexcept {
    if (len % kSnarkvStride != 0) {
        return {nullptr, 0};
    }
    size_t k{len / kSnarkvStride};

    silkpre::init_libff();
    using namespace libff;

    static const auto one{alt_bn128_Fq12::one()};
    auto accumulator{one};

    for (size_t i{0}; i < k; ++i) {
        std::optional<alt_bn128_G1> a{silkpre::decode_g1_element(&input[i * kSnarkvStride])};
        if (!a) {
            return {nullptr, 0};
        }
        std::optional<alt_bn128_G2> b{silkpre::decode_g2_element(&input[i * kSnarkvStride + 64])};
        if (!b) {
            return {nullptr, 0};
        }

        if (a->is_zero() || b->is_zero()) {
            continue;
        }

        accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(*a), alt_bn128_precompute_G2(*b));
    }

    uint8_t* out{static_cast<uint8_t*>(std::malloc(32))};
    std::memset(out, 0, 32);
    if (alt_bn128_final_exponentiation(accumulator) == one) {
        out[31] = 1;
    }
    return {out, 32};
}

uint64_t blake2_f_gas(const uint8_t* input, size_t len, evmc_revision) noexcept {
    if (len < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return endian::load_big_u32(input);
}

Output blake2_f_run(const uint8_t* input, size_t len) noexcept {
    if (len != 213) {
        return {nullptr, 0};
    }
    uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return {nullptr, 0};
    }

    SilkpreBlake2bState state{};
    if (f) {
        state.f[0] = std::numeric_limits<uint64_t>::max();
    }

    static_assert(intx::byte_order_is_little_endian);
    static_assert(sizeof(state.h) == 8 * 8);
    std::memcpy(&state.h, input + 4, 8 * 8);

    uint8_t block[SILKPRE_BLAKE2B_BLOCKBYTES];
    std::memcpy(block, input + 68, SILKPRE_BLAKE2B_BLOCKBYTES);

    std::memcpy(&state.t, input + 196, 8 * 2);

    uint32_t r{endian::load_big_u32(input)};
    silkpre_blake2b_compress(&state, block, r);

    uint8_t* out{static_cast<uint8_t*>(std::malloc(64))};
    std::memcpy(&out[0], &state.h[0], 8 * 8);
    return {out, 64};
}

}  // namespace silkworm::precompiled
