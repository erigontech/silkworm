/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_DB_BITMAP_HPP_
#define SILKWORM_DB_BITMAP_HPP_

#include <optional>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <roaring64map.hh>
#pragma GCC diagnostic pop

#include <silkworm/common/base.hpp>

namespace silkworm::db::bitmap {

// Erigon bitmapdb.ChunkLimit
constexpr size_t kBitmapChunkLimit = 1950;

roaring::Roaring64Map read(ByteView serialized);

// Return the first value in the bitmap that is not less than (i.e. greater or equal to) n,
// or std::nullopt if no such element is found.
// See Erigon SeekInBitmap64.
std::optional<uint64_t> seek(const roaring::Roaring64Map &bitmap, uint64_t n);

// Return cut bitmap of given size limit
roaring::Roaring64Map cut_left(roaring::Roaring64Map &bitmap, uint64_t len);
roaring::Roaring cut_left(roaring::Roaring &bitmap, uint64_t len);

};  // namespace silkworm::db::bitmap

#endif  // !SILKWORM_DB_BITMAP_HPP_
