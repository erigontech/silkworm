/*
* SHA-{224,256}
* (C) 1999-2010,2017 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Modified in 2021 by Andrew Ashikhmin for Silkworm.

Copyright (C) 1999-2021 The Botan Authors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include "sha256.hpp"

#include <silkworm/common/endian.hpp>

namespace {

/**
 * Bit rotation right by a compile-time constant amount
 * @param input the input word
 * @return input rotated right by ROT bits
 */
template <size_t ROT, typename T>
inline constexpr T rotr(T input) {
    static_assert(ROT > 0 && ROT < 8 * sizeof(T), "Invalid rotation constant");
    return static_cast<T>((input >> ROT) | (input << (8 * sizeof(T) - ROT)));
}

template <typename T>
inline constexpr T choose(T mask, T a, T b) {
    // return (mask & a) | (~mask & b);
    return (b ^ (mask & (a ^ b)));
}

template <typename T>
inline constexpr T majority(T a, T b, T c) {
    /*
    Considering each bit of a, b, c individually

    If a xor b is set, then c is the deciding vote.

    If a xor b is not set then either a and b are both set or both unset.
    In either case the value of c doesn't matter, and examining b (or a)
    allows us to determine which case we are in.
    */
    return choose(a ^ b, c, b);
}

}  // namespace

namespace silkworm::crypto {

/*
 * SHA-256 F1 Function
 *
 * Use a macro as many compilers won't inline a function this big,
 * even though it is much faster if inlined.
 */
#define SHA2_32_F(A, B, C, D, E, F, G, H, M1, M2, M3, M4, magic)      \
    do {                                                              \
        uint32_t A_rho = rotr<2>(A) ^ rotr<13>(A) ^ rotr<22>(A);      \
        uint32_t E_rho = rotr<6>(E) ^ rotr<11>(E) ^ rotr<25>(E);      \
        uint32_t M2_sigma = rotr<17>(M2) ^ rotr<19>(M2) ^ (M2 >> 10); \
        uint32_t M4_sigma = rotr<7>(M4) ^ rotr<18>(M4) ^ (M4 >> 3);   \
        H += magic + E_rho + choose(E, F, G) + M1;                    \
        D += H;                                                       \
        H += A_rho + majority(A, B, C);                               \
        M1 += M2_sigma + M3 + M4_sigma;                               \
    } while (0);

/*
 * SHA-224 / SHA-256 compression function
 */
void SHA_256::compress_digest(std::vector<uint32_t>& digest, const uint8_t input[], size_t blocks) {
    uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4], F = digest[5], G = digest[6],
             H = digest[7];

    for (size_t i = 0; i != blocks; ++i) {
        uint32_t W00 = endian::load_big_u32(&input[0]);
        uint32_t W01 = endian::load_big_u32(&input[1]);
        uint32_t W02 = endian::load_big_u32(&input[2]);
        uint32_t W03 = endian::load_big_u32(&input[3]);
        uint32_t W04 = endian::load_big_u32(&input[4]);
        uint32_t W05 = endian::load_big_u32(&input[5]);
        uint32_t W06 = endian::load_big_u32(&input[6]);
        uint32_t W07 = endian::load_big_u32(&input[7]);
        uint32_t W08 = endian::load_big_u32(&input[8]);
        uint32_t W09 = endian::load_big_u32(&input[9]);
        uint32_t W10 = endian::load_big_u32(&input[10]);
        uint32_t W11 = endian::load_big_u32(&input[11]);
        uint32_t W12 = endian::load_big_u32(&input[12]);
        uint32_t W13 = endian::load_big_u32(&input[13]);
        uint32_t W14 = endian::load_big_u32(&input[14]);
        uint32_t W15 = endian::load_big_u32(&input[15]);

        SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x428A2F98);
        SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x71374491);
        SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0xB5C0FBCF);
        SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0xE9B5DBA5);
        SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x3956C25B);
        SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x59F111F1);
        SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x923F82A4);
        SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0xAB1C5ED5);
        SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xD807AA98);
        SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x12835B01);
        SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x243185BE);
        SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x550C7DC3);
        SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x72BE5D74);
        SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0x80DEB1FE);
        SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x9BDC06A7);
        SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC19BF174);

        SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0xE49B69C1);
        SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0xEFBE4786);
        SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x0FC19DC6);
        SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x240CA1CC);
        SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x2DE92C6F);
        SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4A7484AA);
        SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5CB0A9DC);
        SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x76F988DA);
        SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x983E5152);
        SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA831C66D);
        SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xB00327C8);
        SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xBF597FC7);
        SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xC6E00BF3);
        SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD5A79147);
        SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x06CA6351);
        SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x14292967);

        SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x27B70A85);
        SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x2E1B2138);
        SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x4D2C6DFC);
        SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x53380D13);
        SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x650A7354);
        SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x766A0ABB);
        SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x81C2C92E);
        SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x92722C85);
        SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xA2BFE8A1);
        SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA81A664B);
        SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xC24B8B70);
        SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xC76C51A3);
        SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xD192E819);
        SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD6990624);
        SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xF40E3585);
        SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x106AA070);

        SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x19A4C116);
        SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x1E376C08);
        SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x2748774C);
        SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x34B0BCB5);
        SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x391C0CB3);
        SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4ED8AA4A);
        SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5B9CCA4F);
        SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x682E6FF3);
        SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x748F82EE);
        SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x78A5636F);
        SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x84C87814);
        SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x8CC70208);
        SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x90BEFFFA);
        SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xA4506CEB);
        SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xBEF9A3F7);
        SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC67178F2);

        A = (digest[0] += A);
        B = (digest[1] += B);
        C = (digest[2] += C);
        D = (digest[3] += D);
        E = (digest[4] += E);
        F = (digest[5] += F);
        G = (digest[6] += G);
        H = (digest[7] += H);

        input += 64;
    }
}

/*
 * SHA-256 compression function
 */
void SHA_256::compress_n(const uint8_t input[], size_t blocks) { SHA_256::compress_digest(m_digest, input, blocks); }

/*
 * Copy out the digest
 */
Bytes SHA_256::return_out() {
    Bytes output(32, 0);
    for (size_t i{0}; i < 32 / 4; ++i) {
        endian::store_big_u32(&output[i * 4], m_digest[i]);
    }
    return output;
}

/*
 * Clear memory of sensitive data
 */
void SHA_256::clear() {
    MDx_HashFunction::clear();
    m_digest[0] = 0x6A09E667;
    m_digest[1] = 0xBB67AE85;
    m_digest[2] = 0x3C6EF372;
    m_digest[3] = 0xA54FF53A;
    m_digest[4] = 0x510E527F;
    m_digest[5] = 0x9B05688C;
    m_digest[6] = 0x1F83D9AB;
    m_digest[7] = 0x5BE0CD19;
}

}  // namespace silkworm::crypto
