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

#ifndef SILKWORM_COMMON_ENDIAN_HPP_
#define SILKWORM_COMMON_ENDIAN_HPP_

/*
Facilities to deal with byte order/endianness
See https://en.wikipedia.org/wiki/Endianness

The following macros are defined:
SILKWORM_LITTLE_ENDIAN
SILKWORM_BIG_ENDIAN
SILKWORM_BYTE_ORDER

SILKWORM_BYTE_ORDER is equal to SILKWORM_BIG_ENDIAN for big-endian architectures
and to SILKWORM_LITTLE_ENDIAN for little-endian ones (most current architectures).

In addition, SILKWORM_BSWAP16, SILKWORM_BSWAP32, and SILKWORM_BSWAP64 macros are defined
as compiler intrinsics to swap bytes in 16-bit, 32-bit, and 64-bit integers respectively.
*/

#include <cstdint>
#include <cstring>
#include <optional>

#ifdef _WIN32

#include <intrin.h>

#define SILKWORM_BSWAP16 _byteswap_ushort
#define SILKWORM_BSWAP32 _byteswap_ulong
#define SILKWORM_BSWAP64 _byteswap_uint64

// On Windows assume little endian
#define SILKWORM_LITTLE_ENDIAN 1234
#define SILKWORM_BIG_ENDIAN 4321
#define SILKWORM_BYTE_ORDER SILKWORM_LITTLE_ENDIAN

#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)

#define SILKWORM_BSWAP16 __builtin_bswap16
#define SILKWORM_BSWAP32 __builtin_bswap32
#define SILKWORM_BSWAP64 __builtin_bswap64

// https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
#define SILKWORM_LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define SILKWORM_BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define SILKWORM_BYTE_ORDER __BYTE_ORDER__

#else
#error "endianness detection failure"
#endif

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm::endian {

#if SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN
struct le {
    static inline uint16_t uint16(uint16_t value) noexcept { return value; }
    static inline uint32_t uint32(uint32_t value) noexcept { return value; }
    static inline uint64_t uint64(uint64_t value) noexcept { return value; }
};
struct be {
    static inline uint16_t uint16(uint16_t value) noexcept { return SILKWORM_BSWAP16(value); }
    static inline uint32_t uint32(uint32_t value) noexcept { return SILKWORM_BSWAP32(value); }
    static inline uint64_t uint64(uint64_t value) noexcept { return SILKWORM_BSWAP64(value); }
};
#elif SILKWORM_BYTE_ORDER == SILKWORM_BIG_ENDIAN
struct le {
    static inline uint16_t uint16(uint16_t value) noexcept { return SILKWORM_BSWAP16(value); }
    static inline uint32_t uint32(uint32_t value) noexcept { return SILKWORM_BSWAP32(value); }
    static inline uint64_t uint64(uint64_t value) noexcept { return SILKWORM_BSWAP64(value); }
};
struct be {
    static inline uint16_t uint16(uint16_t value) noexcept { return value; }
    static inline uint32_t uint32(uint32_t value) noexcept { return value; }
    static inline uint64_t uint64(uint64_t value) noexcept { return value; }
};
#else
#error "byte order not supported"
#endif

// Similar to boost::endian::load_big_u16
inline uint16_t load_big_u16(const uint8_t* bytes) noexcept {
    uint16_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return be::uint16(x);
}

// Similar to boost::endian::load_big_u32
inline uint32_t load_big_u32(const uint8_t* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return be::uint32(x);
}

// Similar to boost::endian::load_big_u64
inline uint64_t load_big_u64(const uint8_t* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return be::uint64(x);
}

// Similar to boost::endian::load_little_u16
inline uint16_t load_little_u16(const uint8_t* bytes) noexcept {
    uint16_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return le::uint16(x);
}

// Similar to boost::endian::load_little_u32
inline uint32_t load_little_u32(const uint8_t* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return le::uint32(x);
}

// Similar to boost::endian::load_little_u64
inline uint64_t load_little_u64(const uint8_t* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return le::uint64(x);
}

// Similar to boost::endian::store_big_u16
inline void store_big_u16(uint8_t* bytes, const uint16_t value) {
    uint16_t x{be::uint16(value)};
    std::memcpy(bytes, &x, sizeof(x));
}

// Similar to boost::endian::store_big_u32
inline void store_big_u32(uint8_t* bytes, const uint32_t value) {
    uint32_t x{be::uint32(value)};
    std::memcpy(bytes, &x, sizeof(x));
}

// Similar to boost::endian::store_big_u64
inline void store_big_u64(uint8_t* bytes, const uint64_t value) {
    uint64_t x{be::uint64(value)};
    std::memcpy(bytes, &x, sizeof(x));
}

//! \brief Transforms a uint64_t stored in memory with native endianness to it's compacted big endian byte form
//! \param [in] value : the value to be transformed
//! \return A string of bytes
//! \remarks See Erigon TxIndex value
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
Bytes to_big_compact(const uint64_t value);

//! \brief Transforms a uint256 stored in memory with native endianness to it's compacted big endian byte form
//! \param [in] value : the value to be transformed
//! \return A string of bytes
//! \remarks See Erigon TxIndex value
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
Bytes to_big_compact(const intx::uint256& value);

//! \brief Parses uint64_t from a compacted big endian byte form
//! \param [in] data : byteview of memory allocation for compacted value. Length must be <= sizeof(uint64_t)
//! \param [in] allow_leading_zeros : when false, return std::nullopt if data starts with a 0 byte (not compact)
//! \return A uint64_t with native endianness; std::nullopt if data is invalid
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
std::optional<uint64_t> from_big_compact_u64(const ByteView& data, bool allow_leading_zeros = false);

//! \brief Parses uint256 from a compacted big endian byte form
//! \param [in] data : byteview of memory allocation for compacted value. Length must be <= sizeof(uint256)
//! \param [in] allow_leading_zeros : when false, return std::nullopt if data starts with a 0 byte (not compact)
//! \return A uint256 with native endianness; std::nullopt if data is invalid
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
std::optional<intx::uint256> from_big_compact_u256(const ByteView& data, bool allow_leading_zeros = false);

}  // namespace silkworm::endian

#endif  // SILKWORM_COMMON_ENDIAN_HPP_
