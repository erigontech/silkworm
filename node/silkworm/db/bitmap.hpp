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

#pragma once

#include <optional>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <roaring64map.hh>
#pragma GCC diagnostic pop

#include <silkworm/common/base.hpp>
#include <silkworm/db/mdbx.hpp>

namespace silkworm::db::bitmap {

// Erigon bitmapdb.ChunkLimit
// Value is obtained as threshold beyond which MDBX overflow pages : i.e. 4096 / 2 - (keySize + 8)
// TODO Adjust for case when pagesize is 8192
inline constexpr size_t kBitmapChunkLimit = 1950;

roaring::Roaring64Map read(ByteView serialized);

// Return the first value in the bitmap that is not less than (i.e. greater or equal to) n,
// or std::nullopt if no such element is found.
// See Erigon SeekInBitmap64.
std::optional<uint64_t> seek(const roaring::Roaring64Map& bitmap, uint64_t n);

// Remove from a bitmap and return its biggest left part not exceeding a given size
roaring::Roaring64Map cut_left(roaring::Roaring64Map& bitmap, uint64_t size_limit);

// Remove from a bitmap and return its biggest left part not exceeding a given size
roaring::Roaring cut_left(roaring::Roaring& bitmap, uint64_t size_limit);

//! \brief Returns Bytes of Roaring64Map data
Bytes to_bytes(roaring::Roaring64Map& bitmap);

//! \brief Returns Roaring64Map from MDBX's slice;
roaring::Roaring64Map from_slice(mdbx::slice& data);

//! \brief Returns Roaring64Map from Bytes/Byteview;
roaring::Roaring64Map from_bytes(ByteView data);

}  // namespace silkworm::db::bitmap
