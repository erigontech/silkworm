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

#include "precompile.hpp"

#include <gmp.h>

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

#include <evmone_precompiles/blake2b.hpp>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/ripemd160.hpp>
#include <evmone_precompiles/sha256.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>
#pragma GCC diagnostic pop

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::precompile {

static void right_pad(Bytes& str, const size_t min_size) noexcept {
    if (str.size() < min_size) {
        str.resize(min_size, '\0');
    }
}

uint64_t ecrec_gas(ByteView, evmc_revision) noexcept { return 3'000; }

std::optional<Bytes> ecrec_run(ByteView input) noexcept {
    Bytes d{input};
    right_pad(d, 128);

    const auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    const auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    const auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    const bool homestead{false};  // See EIP-2
    if (!is_valid_signature(r, s, homestead)) {
        return Bytes{};
    }

    if (v != 27 && v != 28) {
        return Bytes{};
    }

    Bytes out(32, 0);
    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    if (!silkworm_recover_address(&out[12], &d[0], &d[64], v != 27, context)) {
        return Bytes{};
    }
    return out;
}

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept {
    return 60 + 12 * num_words(input.size());
}

std::optional<Bytes> sha256_run(ByteView input) noexcept {
    Bytes out(32, 0);
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(out.data()),
                           reinterpret_cast<const std::byte*>(input.data()),
                           input.size());
    return out;
}

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept {
    return 600 + 120 * num_words(input.size());
}

std::optional<Bytes> rip160_run(ByteView input) noexcept {
    Bytes out(32, 0);
    SILKWORM_ASSERT(input.size() <= std::numeric_limits<uint32_t>::max());
    evmone::crypto::ripemd160(reinterpret_cast<std::byte*>(&out[12]),
                              reinterpret_cast<const std::byte*>(input.data()),
                              input.size());
    return out;
}

uint64_t id_gas(ByteView input, evmc_revision) noexcept {
    return 15 + 3 * num_words(input.size());
}

std::optional<Bytes> id_run(ByteView input) noexcept {
    return Bytes{input};
}

static intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept {
    const intx::uint256 x_squared{x * x};
    if (x <= 64) {
        return x_squared;
    }
    if (x <= 1024) {
        return (x_squared >> 2) + 96 * x - 3072;
    }
    return (x_squared >> 4) + 480 * x - 199680;
}

static intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept {
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

uint64_t expmod_gas(ByteView input_view, evmc_revision rev) noexcept {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};

    Bytes input{input_view};
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
    if (input.size() > base_len64) {
        input.erase(0, static_cast<size_t>(base_len64));
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(static_cast<size_t>(exp_len64));
            input.insert(0, 32 - static_cast<size_t>(exp_len64), '\0');
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
    }
    return std::max(min_gas, static_cast<uint64_t>(gas));
}

std::optional<Bytes> expmod_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 3 * 32);

    uint64_t base_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    uint64_t exponent_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    uint64_t modulus_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    if (modulus_len == 0) {
        return Bytes{};
    }

    right_pad(input, static_cast<size_t>(base_len + exponent_len + modulus_len));

    mpz_t base;
    mpz_init(base);
    if (base_len) {
        mpz_import(base, base_len, 1, 1, 0, 0, input.data());
        input.erase(0, static_cast<size_t>(base_len));
    }

    mpz_t exponent;
    mpz_init(exponent);
    if (exponent_len) {
        mpz_import(exponent, exponent_len, 1, 1, 0, 0, input.data());
        input.erase(0, static_cast<size_t>(exponent_len));
    }

    mpz_t modulus;
    mpz_init(modulus);
    mpz_import(modulus, modulus_len, 1, 1, 0, 0, input.data());

    Bytes out(static_cast<size_t>(modulus_len), 0);

    if (mpz_sgn(modulus) == 0) {
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return out;
    }

    mpz_t result;
    mpz_init(result);

    mpz_powm(result, base, exponent, modulus);

    // export as little-endian
    mpz_export(out.data(), nullptr, -1, 1, 0, 0, result);
    // and convert to big-endian
    std::ranges::reverse(out);

    mpz_clear(result);
    mpz_clear(modulus);
    mpz_clear(exponent);
    mpz_clear(base);

    return out;
}

// Utility functions for zkSNARK related precompiled contracts.
// See Yellow Paper, Appendix E "Precompiled Contracts", as well as
// EIP-196: Precompiled contracts for addition and scalar multiplication on the elliptic curve alt_bn128
// EIP-197: Precompiled contracts for optimal ate pairing check on the elliptic curve alt_bn128
using Scalar = libff::bigint<libff::alt_bn128_q_limbs>;

// Must be called prior to invoking any other method.
// May be called many times from multiple threads.
static void init_libff() noexcept {
    // magic static
    [[maybe_unused]] static bool initialized = []() noexcept {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
}

static Scalar to_scalar(const uint8_t bytes_be[32]) noexcept {
    mpz_t m;
    mpz_init(m);
    mpz_import(m, 32, /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, bytes_be);
    Scalar out{m};
    mpz_clear(m);
    return out;
}

// Notation warning: Yellow Paper's p is the same libff's q.
// Returns x < p (YP notation).
static bool valid_element_of_fp(const Scalar& x) noexcept {
    return mpn_cmp(x.data, libff::alt_bn128_modulus_q.data, libff::alt_bn128_q_limbs) < 0;
}

static std::optional<libff::alt_bn128_G1> decode_g1_element(const uint8_t bytes_be[64]) noexcept {
    Scalar x{to_scalar(bytes_be)};
    if (!valid_element_of_fp(x)) {
        return {};
    }

    Scalar y{to_scalar(bytes_be + 32)};
    if (!valid_element_of_fp(y)) {
        return {};
    }

    if (x.is_zero() && y.is_zero()) {
        return libff::alt_bn128_G1::zero();
    }

    libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
    if (!point.is_well_formed()) {
        return {};
    }
    return point;
}

static std::optional<libff::alt_bn128_Fq2> decode_fp2_element(const uint8_t bytes_be[64]) noexcept {
    // big-endian encoding
    Scalar c0{to_scalar(bytes_be + 32)};
    Scalar c1{to_scalar(bytes_be)};

    if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
        return {};
    }

    return libff::alt_bn128_Fq2{c0, c1};
}

static std::optional<libff::alt_bn128_G2> decode_g2_element(const uint8_t bytes_be[128]) noexcept {
    std::optional<libff::alt_bn128_Fq2> x{decode_fp2_element(bytes_be)};
    if (!x) {
        return {};
    }

    std::optional<libff::alt_bn128_Fq2> y{decode_fp2_element(bytes_be + 64)};
    if (!y) {
        return {};
    }

    if (x->is_zero() && y->is_zero()) {
        return libff::alt_bn128_G2::zero();
    }

    libff::alt_bn128_G2 point{*x, *y, libff::alt_bn128_Fq2::one()};
    if (!point.is_well_formed()) {
        return {};
    }

    if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
        // wrong order, doesn't belong to the subgroup G2
        return {};
    }

    return point;
}

static Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
    Bytes out(64, '\0');
    if (p.is_zero()) {
        return out;
    }

    p.to_affine_coordinates();

    auto x{p.X.as_bigint()};
    auto y{p.Y.as_bigint()};

    // Here we convert little-endian data to big-endian output
    static_assert(sizeof(x.data) == 32);

    std::memcpy(&out[0], y.data, 32);
    std::memcpy(&out[32], x.data, 32);

    std::ranges::reverse(out);
    return out;
}

uint64_t bn_add_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 150 : 500;
}

std::optional<Bytes> bn_add_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 128);

    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return std::nullopt;
    }

    std::optional<libff::alt_bn128_G1> y{decode_g1_element(&input[64])};
    if (!y) {
        return std::nullopt;
    }

    libff::alt_bn128_G1 sum{*x + *y};
    return encode_g1_element(sum);
}

uint64_t bn_mul_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 6'000 : 40'000;
}

std::optional<Bytes> bn_mul_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 96);

    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return std::nullopt;
    }

    Scalar n{to_scalar(&input[64])};

    libff::alt_bn128_G1 product{n * *x};
    return encode_g1_element(product);
}

static constexpr size_t kSnarkvStride{192};

uint64_t snarkv_gas(ByteView input, evmc_revision rev) noexcept {
    uint64_t k{input.size() / kSnarkvStride};
    return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

std::optional<Bytes> snarkv_run(ByteView input) noexcept {
    if (input.size() % kSnarkvStride != 0) {
        return std::nullopt;
    }
    size_t k{input.size() / kSnarkvStride};

    init_libff();
    using namespace libff;

    static const auto kOne{alt_bn128_Fq12::one()};
    auto accumulator{kOne};

    for (size_t i{0}; i < k; ++i) {
        std::optional<alt_bn128_G1> a{decode_g1_element(&input[i * kSnarkvStride])};
        if (!a) {
            return std::nullopt;
        }
        std::optional<alt_bn128_G2> b{decode_g2_element(&input[i * kSnarkvStride + 64])};
        if (!b) {
            return std::nullopt;
        }

        if (a->is_zero() || b->is_zero()) {
            continue;
        }

        accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(*a), alt_bn128_precompute_G2(*b));
    }

    Bytes out(32, 0);
    if (alt_bn128_final_exponentiation(accumulator) == kOne) {
        out[31] = 1;
    }
    return out;
}

uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept {
    if (input.size() < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return endian::load_big_u32(input.data());
}

std::optional<Bytes> blake2_f_run(ByteView input) noexcept {
    if (input.size() != 213) {
        return std::nullopt;
    }
    const uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return std::nullopt;
    }

    uint64_t h[8];
    std::memcpy(h, &input[4], sizeof(h));
    uint64_t m[16];
    std::memcpy(m, &input[68], sizeof(m));
    uint64_t t[2];
    std::memcpy(t, &input[196], sizeof(t));

    static_assert(std::endian::native == std::endian::little);

    uint32_t r{endian::load_big_u32(input.data())};
    evmone::crypto::blake2b_compress(r, h, m, t, f != 0);

    Bytes out(sizeof(h), 0);
    std::memcpy(&out[0], h, sizeof(h));
    return out;
}

uint64_t point_evaluation_gas(ByteView, evmc_revision) noexcept {
    return 50000;
}

// https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
std::optional<Bytes> point_evaluation_run(ByteView input) noexcept {
    if (input.size() != 192) {
        return std::nullopt;
    }

    std::span<const uint8_t, 32> versioned_hash{&input[0], 32};
    std::span<const uint8_t, 32> z{&input[32], 32};
    std::span<const uint8_t, 32> y{&input[64], 32};
    std::span<const uint8_t, 48> commitment{&input[96], 48};
    std::span<const uint8_t, 48> proof{&input[144], 48};

    if (!evmone::crypto::kzg_verify_proof(
            std::as_bytes(versioned_hash).data(),
            std::as_bytes(z).data(),
            std::as_bytes(y).data(),
            std::as_bytes(commitment).data(),
            std::as_bytes(proof).data())) {
        return std::nullopt;
    }

    return from_hex(
        "0000000000000000000000000000000000000000000000000000000000001000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}

bool is_precompile(const evmc::address& address, evmc_revision rev) noexcept {
    using namespace evmc::literals;

    static_assert(std::size(kContracts) < 256);
    static constexpr evmc::address kMaxOneByteAddress{0x00000000000000000000000000000000000000ff_address};
    if (address > kMaxOneByteAddress) {
        return false;
    }

    const uint8_t num{address.bytes[kAddressLength - 1]};
    if (num >= std::size(kContracts) || !kContracts[num]) {
        return false;
    }

    return kContracts[num]->added_in <= rev;
}

}  // namespace silkworm::precompile
