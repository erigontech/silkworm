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

//
// SpookyHash: a 128-bit noncryptographic hash function
// By Bob Jenkins, public domain
//   Oct 31 2010: alpha, framework + SpookyHash::Mix appears right
//   Oct 31 2011: alpha again, Mix only good to 2^^69 but rest appears right
//   Dec 31 2011: beta, improved Mix, tested it for 2-bit deltas
//   Feb  2 2012: production, same bits as beta
//   Feb  5 2012: adjusted definitions of uint* to be more portable
//   Mar 30 2012: 3 bytes/cycle, not 4.  Alpha was 4 but wasn't thorough enough.
//   August 5 2012: SpookyV2 (different results)
//
// Up to 3 bytes/cycle for long messages.  Reasonably fast for short messages.
// All 1 or 2 bit deltas achieve avalanche within 1% bias per output bit.
//
// This was developed for and tested on 64-bit x86-compatible processors.
// It assumes the processor is little-endian.  There is a macro
// controlling whether unaligned reads are allowed (by default they are).
// This should be an equally good hash on big-endian machines, but it will
// compute different results on them than on little-endian machines.
//
// Google's CityHash has similar specs to SpookyHash, and CityHash is faster
// on new Intel boxes.  MD4 and MD5 also have similar specs, but they are orders
// of magnitude slower.  CRCs are two or more times slower, but unlike
// SpookyHash, they have nice math for combining the CRCs of pieces to form
// the CRCs of wholes.  There are also cryptographic hashes, but those are even
// slower than MD5.
//

#include <cstddef>
#include <cstdint>
#include <cstring>

#define ALLOW_UNALIGNED_READS 1

class SpookyHash {
  private:
    static inline uint64_t Rot64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

    //
    // This is used if the input is 96 bytes long or longer.
    //
    // The internal state is fully overwritten every 96 bytes.
    // Every input bit appears to cause at least 128 bits of entropy
    // before 96 other bytes are combined, when run forward or backward
    //   For every input bit,
    //   Two inputs differing in just that input bit
    //   Where "differ" means xor or subtraction
    //   And the base value is random
    //   When run forward or backwards one Mix
    // I tried 3 pairs of each; they all differed by at least 212 bits.
    //
    static inline void Mix(const uint64_t* data, uint64_t& s0, uint64_t& s1, uint64_t& s2, uint64_t& s3, uint64_t& s4, uint64_t& s5, uint64_t& s6, uint64_t& s7, uint64_t& s8, uint64_t& s9,
                           uint64_t& s10, uint64_t& s11) {
        s0 += data[0];
        s2 ^= s10;
        s11 ^= s0;
        s0 = Rot64(s0, 11);
        s11 += s1;
        s1 += data[1];
        s3 ^= s11;
        s0 ^= s1;
        s1 = Rot64(s1, 32);
        s0 += s2;
        s2 += data[2];
        s4 ^= s0;
        s1 ^= s2;
        s2 = Rot64(s2, 43);
        s1 += s3;
        s3 += data[3];
        s5 ^= s1;
        s2 ^= s3;
        s3 = Rot64(s3, 31);
        s2 += s4;
        s4 += data[4];
        s6 ^= s2;
        s3 ^= s4;
        s4 = Rot64(s4, 17);
        s3 += s5;
        s5 += data[5];
        s7 ^= s3;
        s4 ^= s5;
        s5 = Rot64(s5, 28);
        s4 += s6;
        s6 += data[6];
        s8 ^= s4;
        s5 ^= s6;
        s6 = Rot64(s6, 39);
        s5 += s7;
        s7 += data[7];
        s9 ^= s5;
        s6 ^= s7;
        s7 = Rot64(s7, 57);
        s6 += s8;
        s8 += data[8];
        s10 ^= s6;
        s7 ^= s8;
        s8 = Rot64(s8, 55);
        s7 += s9;
        s9 += data[9];
        s11 ^= s7;
        s8 ^= s9;
        s9 = Rot64(s9, 54);
        s8 += s10;
        s10 += data[10];
        s0 ^= s8;
        s9 ^= s10;
        s10 = Rot64(s10, 22);
        s9 += s11;
        s11 += data[11];
        s1 ^= s9;
        s10 ^= s11;
        s11 = Rot64(s11, 46);
        s10 += s0;
    }

    //
    // Mix all 12 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3%
    // For every pair of input bits,
    // with probability 50 +- 3%
    //
    // This does not rely on the last Mix() call having already mixed some.
    // Two iterations was almost good enough for a 64-bit result, but a
    // 128-bit result is reported, so End() does three iterations.
    //
    static inline void EndPartial(uint64_t& h0, uint64_t& h1, uint64_t& h2, uint64_t& h3, uint64_t& h4, uint64_t& h5, uint64_t& h6, uint64_t& h7, uint64_t& h8, uint64_t& h9, uint64_t& h10,
                                  uint64_t& h11) {
        h11 += h1;
        h2 ^= h11;
        h1 = Rot64(h1, 44);
        h0 += h2;
        h3 ^= h0;
        h2 = Rot64(h2, 15);
        h1 += h3;
        h4 ^= h1;
        h3 = Rot64(h3, 34);
        h2 += h4;
        h5 ^= h2;
        h4 = Rot64(h4, 21);
        h3 += h5;
        h6 ^= h3;
        h5 = Rot64(h5, 38);
        h4 += h6;
        h7 ^= h4;
        h6 = Rot64(h6, 33);
        h5 += h7;
        h8 ^= h5;
        h7 = Rot64(h7, 10);
        h6 += h8;
        h9 ^= h6;
        h8 = Rot64(h8, 13);
        h7 += h9;
        h10 ^= h7;
        h9 = Rot64(h9, 38);
        h8 += h10;
        h11 ^= h8;
        h10 = Rot64(h10, 53);
        h9 += h11;
        h0 ^= h9;
        h11 = Rot64(h11, 42);
        h10 += h0;
        h1 ^= h10;
        h0 = Rot64(h0, 54);
    }

    static inline void End(const uint64_t* data, uint64_t& h0, uint64_t& h1, uint64_t& h2, uint64_t& h3, uint64_t& h4, uint64_t& h5, uint64_t& h6, uint64_t& h7, uint64_t& h8, uint64_t& h9,
                           uint64_t& h10, uint64_t& h11) {
        h0 += data[0];
        h1 += data[1];
        h2 += data[2];
        h3 += data[3];
        h4 += data[4];
        h5 += data[5];
        h6 += data[6];
        h7 += data[7];
        h8 += data[8];
        h9 += data[9];
        h10 += data[10];
        h11 += data[11];
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
    }

    //
    // The goal is for each bit of the input to expand into 128 bits of
    //   apparent entropy before it is fully overwritten.
    // n trials both set and cleared at least m bits of h0 h1 h2 h3
    //   n: 2   m: 29
    //   n: 3   m: 46
    //   n: 4   m: 57
    //   n: 5   m: 107
    //   n: 6   m: 146
    //   n: 7   m: 152
    // when run forwards or backwards
    // for all 1-bit and 2-bit diffs
    // with diffs defined by either xor or subtraction
    // with a base of all zeros plus a counter, or plus another bit, or random
    //
    static inline void ShortMix(uint64_t& h0, uint64_t& h1, uint64_t& h2, uint64_t& h3) {
        h2 = Rot64(h2, 50);
        h2 += h3;
        h0 ^= h2;
        h3 = Rot64(h3, 52);
        h3 += h0;
        h1 ^= h3;
        h0 = Rot64(h0, 30);
        h0 += h1;
        h2 ^= h0;
        h1 = Rot64(h1, 41);
        h1 += h2;
        h3 ^= h1;
        h2 = Rot64(h2, 54);
        h2 += h3;
        h0 ^= h2;
        h3 = Rot64(h3, 48);
        h3 += h0;
        h1 ^= h3;
        h0 = Rot64(h0, 38);
        h0 += h1;
        h2 ^= h0;
        h1 = Rot64(h1, 37);
        h1 += h2;
        h3 ^= h1;
        h2 = Rot64(h2, 62);
        h2 += h3;
        h0 ^= h2;
        h3 = Rot64(h3, 34);
        h3 += h0;
        h1 ^= h3;
        h0 = Rot64(h0, 5);
        h0 += h1;
        h2 ^= h0;
        h1 = Rot64(h1, 36);
        h1 += h2;
        h3 ^= h1;
    }

    //
    // Mix all 4 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3% (it is probably better than that)
    // For every pair of input bits,
    // with probability 50 +- .75% (the worst case is approximately that)
    //
    static inline void ShortEnd(uint64_t& h0, uint64_t& h1, uint64_t& h2, uint64_t& h3) {
        h3 ^= h2;
        h2 = Rot64(h2, 15);
        h3 += h2;
        h0 ^= h3;
        h3 = Rot64(h3, 52);
        h0 += h3;
        h1 ^= h0;
        h0 = Rot64(h0, 26);
        h1 += h0;
        h2 ^= h1;
        h1 = Rot64(h1, 51);
        h2 += h1;
        h3 ^= h2;
        h2 = Rot64(h2, 28);
        h3 += h2;
        h0 ^= h3;
        h3 = Rot64(h3, 9);
        h0 += h3;
        h1 ^= h0;
        h0 = Rot64(h0, 47);
        h1 += h0;
        h2 ^= h1;
        h1 = Rot64(h1, 54);
        h2 += h1;
        h3 ^= h2;
        h2 = Rot64(h2, 32);
        h3 += h2;
        h0 ^= h3;
        h3 = Rot64(h3, 25);
        h0 += h3;
        h1 ^= h0;
        h0 = Rot64(h0, 63);
        h1 += h0;
    }

  private:
    // number of uint64_t's in internal state
    static const size_t sc_numVars = 12;

    // size of the internal state
    static const size_t sc_blockSize = sc_numVars * 8;

    // size of buffer of unhashed data, in bytes
    static const size_t sc_bufSize = 2 * sc_blockSize;

    //
    // sc_const: a constant which:
    //  * is not zero
    //  * is odd
    //  * is a not-very-regular mix of 1's and 0's
    //  * does not need any other special mathematical properties
    //
    static const uint64_t sc_const = 0xdeadbeefdeadbeefLL;

  public:
    /** Hashes short data to 128 bits.
     *
     * This version has a lower startup cost, and it is more efficient
     * on short (less than about 200 characters) strings.
     *
     * @param data bytes to hash.
     * @param length number of valid bytes in `data`.
     * @param hash1 in seed 1, out hash 1.
     * @param hash2 in seed 2, out hash 2.
     */
    static void Short128(const void* data, size_t length, uint64_t* hash1, uint64_t* hash2) {
        uint64_t buf[2 * sc_numVars];
        union {
            const uint8_t* p8;
            uint32_t* p32;
            uint64_t* p64;
            size_t i;
        } u;

        u.p8 = static_cast<const uint8_t*>(data);

        if (!ALLOW_UNALIGNED_READS && (u.i & 0x7)) {
            memcpy(buf, data, length);
            u.p64 = buf;
        }

        size_t remainder = length % 32;
        uint64_t a = *hash1;
        uint64_t b = *hash2;
        uint64_t c = sc_const;
        uint64_t d = sc_const;

        if (length > 15) {
            const uint64_t* end = u.p64 + (length / 32) * 4;

            // handle all complete sets of 32 bytes
            for (; u.p64 < end; u.p64 += 4) {
                c += u.p64[0];
                d += u.p64[1];
                ShortMix(a, b, c, d);
                a += u.p64[2];
                b += u.p64[3];
            }

            // Handle the case of 16+ remaining bytes.
            if (remainder >= 16) {
                c += u.p64[0];
                d += u.p64[1];
                ShortMix(a, b, c, d);
                u.p64 += 2;
                remainder -= 16;
            }
        }

        // Handle the last 0..15 bytes, and its length
        d += (static_cast<uint64_t>(length)) << 56;
        switch (remainder) {
            case 15:
                d += (static_cast<uint64_t>(u.p8[14])) << 48;
            case 14:
                d += (static_cast<uint64_t>(u.p8[13])) << 40;
            case 13:
                d += (static_cast<uint64_t>(u.p8[12])) << 32;
            case 12:
                d += u.p32[2];
                c += u.p64[0];
                break;
            case 11:
                d += (static_cast<uint64_t>(u.p8[10])) << 16;
            case 10:
                d += (static_cast<uint64_t>(u.p8[9])) << 8;
            case 9:
                d += static_cast<uint64_t>(u.p8[8]);
            case 8:
                c += u.p64[0];
                break;
            case 7:
                c += (static_cast<uint64_t>(u.p8[6])) << 48;
            case 6:
                c += (static_cast<uint64_t>(u.p8[5])) << 40;
            case 5:
                c += (static_cast<uint64_t>(u.p8[4])) << 32;
            case 4:
                c += u.p32[0];
                break;
            case 3:
                c += (static_cast<uint64_t>(u.p8[2])) << 16;
            case 2:
                c += (static_cast<uint64_t>(u.p8[1])) << 8;
            case 1:
                c += static_cast<uint64_t>(u.p8[0]);
                break;
            case 0:
                c += sc_const;
                d += sc_const;
        }
        ShortEnd(a, b, c, d);
        *hash1 = a;
        *hash2 = b;
    }

    /** Hashes short data to 75 bits.
     *
     * This version has a lower startup cost, and it is more efficient
     * on short (less than about 200 characters) strings.
     *
     * @param data bytes to hash.
     * @param length number of valid bytes in `data`.
     * @param seed a seed.
     * @return a 64-bit hash.
     */
    static uint64_t Short64(const void* data, size_t length, uint64_t seed) {
        uint64_t hash1 = seed;
        Short128(data, length, &hash1, &seed);
        return hash1;
    }

    /** Hashes long data to 128 bits.
     *
     * This version has a higher startup cost, and it is more efficient
     * on long (more than about 200 characters) strings.
     *
     * @param data bytes to hash.
     * @param length number of valid bytes in `data`.
     * @param hash1 in seed 1, out hash 1.
     * @param hash2 in seed 2, out hash 2.
     */
    static void Hash128(const void* data, size_t length, uint64_t* hash1, uint64_t* hash2) {
        if (length < sc_bufSize) {
            Short128(data, length, hash1, hash2);
            return;
        }

        uint64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
        uint64_t buf[sc_numVars];
        uint64_t* end;
        union {
            const uint8_t* p8;
            uint64_t* p64;
            size_t i;
        } u;
        size_t remainder;

        h0 = h3 = h6 = h9 = *hash1;
        h1 = h4 = h7 = h10 = *hash2;
        h2 = h5 = h8 = h11 = sc_const;

        u.p8 = static_cast<const uint8_t*>(data);
        end = u.p64 + (length / sc_blockSize) * sc_numVars;

        // handle all whole sc_blockSize blocks of bytes
        if (ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0)) {
            while (u.p64 < end) {
                Mix(u.p64, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
                u.p64 += sc_numVars;
            }
        } else {
            while (u.p64 < end) {
                memcpy(buf, u.p64, sc_blockSize);
                Mix(buf, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
                u.p64 += sc_numVars;
            }
        }

        // handle the last partial block of sc_blockSize bytes
        remainder = (length - static_cast<size_t>(reinterpret_cast<const uint8_t*>(end) - static_cast<const uint8_t*>(data)));
        memcpy(buf, end, remainder);
        memset((reinterpret_cast<uint8_t*>(buf)) + remainder, 0, sc_blockSize - remainder);
        (reinterpret_cast<uint8_t*>(buf))[sc_blockSize - 1] = remainder;

        // do some final mixing
        End(buf, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        *hash1 = h0;
        *hash2 = h1;
    }

    /** Hashes long data to 64 bits.
     *
     * This version has a higher startup cost, and it is more efficient
     * on long (more than about 200 characters) strings.
     *
     * @param data bytes to hash.
     * @param length number of valid bytes in `data`.
     * @param seed a seed.
     * @return a 64-bit hash.
     */
    static uint64_t Hash64(const void* data, size_t length, uint64_t seed) {
        uint64_t hash1 = seed;
        Hash128(data, length, &hash1, &seed);
        return hash1;
    }
};
