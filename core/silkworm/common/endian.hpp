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

#ifndef SILKWORM_COMMON_ENDIAN_HPP_
#define SILKWORM_COMMON_ENDIAN_HPP_

/*
Facilities to deal with byte order/endianness
See https://en.wikipedia.org/wiki/Endianness
*/

#include <cstdint>
#include <cstring>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>

namespace silkworm::endian {

// Similar to boost::endian::load_big_u16
inline uint16_t load_big_u16(const uint8_t* bytes) noexcept { return intx::be::unsafe::load<uint16_t>(bytes); }

// Similar to boost::endian::load_big_u32
inline uint32_t load_big_u32(const uint8_t* bytes) noexcept { return intx::be::unsafe::load<uint32_t>(bytes); }

// Similar to boost::endian::load_big_u64
inline uint64_t load_big_u64(const uint8_t* bytes) noexcept { return intx::be::unsafe::load<uint64_t>(bytes); }

// Similar to boost::endian::load_little_u16
inline uint16_t load_little_u16(const uint8_t* bytes) noexcept { return intx::le::unsafe::load<uint16_t>(bytes); }

// Similar to boost::endian::load_little_u32
inline uint32_t load_little_u32(const uint8_t* bytes) noexcept { return intx::le::unsafe::load<uint32_t>(bytes); }

// Similar to boost::endian::load_little_u64
inline uint64_t load_little_u64(const uint8_t* bytes) noexcept { return intx::le::unsafe::load<uint64_t>(bytes); }

// Similar to boost::endian::store_big_u16
inline void store_big_u16(uint8_t* bytes, const uint16_t value) { intx::be::unsafe::store(bytes, value); }

// Similar to boost::endian::store_big_u32
inline void store_big_u32(uint8_t* bytes, const uint32_t value) { intx::be::unsafe::store(bytes, value); }

// Similar to boost::endian::store_big_u64
inline void store_big_u64(uint8_t* bytes, const uint64_t value) { intx::be::unsafe::store(bytes, value); }

//! \brief Transforms a uint64_t stored in memory with native endianness to it's compacted big endian byte form
//! \param [in] value : the value to be transformed
//! \return A ByteView (std::string_view) into an internal static buffer (thread specific) of the function
//! \remarks each function call overwrites the buffer, therefore invalidating a previously returned result
//! \remarks so each returned ByteView must be used immediately (before a further call to the same function).
//! \remarks See Erigon TxIndex value
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
ByteView to_big_compact(uint64_t value);

//! \brief Transforms a uint256 stored in memory with native endianness to it's compacted big endian byte form
//! \param [in] value : the value to be transformed
//! \return A ByteView (std::string_view) into an internal static buffer (thread specific) of the function
//! \remarks each function call overwrites the buffer, therefore invalidating a previously returned result
//! \remarks so each returned ByteView must be used immediately (before a further call to the same function)
//! \remarks See Erigon TxIndex value
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
ByteView to_big_compact(const intx::uint256& value);

//! \brief Parses unsigned integer from a compacted big endian byte form.
//! \param [in] data : byte view of compacted value. Length must be <= sizeof(UnsignedInteger);
//! otherwise kOverflow is returned.
//! \param [out] out: the corresponding integer with native endianness.
//! \return kOk or kOverflow or kLeadingZero.
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero;
//! if the input is not compact kLeadingZero is returned.
template <typename UnsignedInteger>
static DecodingResult from_big_compact(ByteView data, UnsignedInteger& out) {
    if (data.length() > sizeof(UnsignedInteger)) {
        return DecodingResult::kOverflow;
    }

    out = 0;
    if (data.empty()) {
        return DecodingResult::kOk;
    }

    if (data[0] == 0) {
        return DecodingResult::kLeadingZero;
    }

    auto* ptr{reinterpret_cast<uint8_t*>(&out)};
    std::memcpy(ptr + (sizeof(UnsignedInteger) - data.length()), &data[0], data.length());

    out = intx::to_big_endian(out);
    return DecodingResult::kOk;
}

}  // namespace silkworm::endian

#endif  // SILKWORM_COMMON_ENDIAN_HPP_
