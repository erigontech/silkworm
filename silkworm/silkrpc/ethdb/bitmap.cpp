/*
   Copyright 2023 The Silkworm Authors

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

#include "bitmap.hpp"

#include <climits>
#include <memory>
#include <utility>
#include <vector>

#include <boost/endian/conversion.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>

namespace silkworm::rpc::ethdb::bitmap {

using roaring_bitmap_t = roaring::api::roaring_bitmap_t;
using Roaring = roaring::Roaring;

static Roaring fast_or(size_t n, const std::vector<std::unique_ptr<Roaring>>& inputs) {
    const auto** x = static_cast<const roaring_bitmap_t**>(malloc(n * sizeof(roaring_bitmap_t*)));
    if (x == nullptr) {
        throw std::runtime_error("failed memory alloc in fast_or");
    }
    for (size_t k = 0; k < n; ++k) {
        x[k] = &inputs[k]->roaring;
    }

    roaring_bitmap_t* c_ans = roaring_bitmap_or_many(n, x);
    if (c_ans == nullptr) {
        free(x);
        throw std::runtime_error("failed memory alloc in fast_or");
    }
    Roaring ans(c_ans);
    free(x);
    return ans;
}

boost::asio::awaitable<Roaring> get(core::rawdb::DatabaseReader& db_reader, const std::string& table, silkworm::Bytes& key, uint32_t from_block, uint32_t to_block) {
    std::vector<std::unique_ptr<Roaring>> chunks;

    silkworm::Bytes from_key{key.begin(), key.end()};
    from_key.resize(key.size() + sizeof(uint32_t));
    boost::endian::store_big_u32(&from_key[key.size()], from_block);
    SILKRPC_DEBUG << "table: " << table << " key: " << key << " from_key: " << from_key << "\n";

    core::rawdb::Walker walker = [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
        SILKRPC_TRACE << "k: " << k << " v: " << v << "\n";
        auto chunk = std::make_unique<Roaring>(Roaring::readSafe(reinterpret_cast<const char*>(v.data()), v.size()));
        SILKRPC_TRACE << "chunk: " << chunk->toString() << "\n";
        chunks.push_back(std::move(chunk));
        auto block = boost::endian::load_big_u32(&k[k.size() - sizeof(uint32_t)]);
        return block < to_block;
    };
    co_await db_reader.walk(table, from_key, key.size() * CHAR_BIT, walker);

    auto result{fast_or(chunks.size(), chunks)};
    SILKRPC_DEBUG << "result: " << result.toString() << "\n";
    co_return result;
}

}  // namespace silkworm::rpc::ethdb::bitmap
