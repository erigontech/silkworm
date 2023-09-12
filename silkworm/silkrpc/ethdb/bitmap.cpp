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

#include <gsl/narrow>

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>

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

Task<Roaring> get(
    core::rawdb::DatabaseReader& db_reader,
    const std::string& table,
    silkworm::Bytes& key,
    uint32_t from_block,
    uint32_t to_block) {
    std::vector<std::unique_ptr<Roaring>> chunks;

    silkworm::Bytes from_key{key.begin(), key.end()};
    from_key.resize(key.size() + sizeof(uint32_t));
    endian::store_big_u32(&from_key[key.size()], from_block);
    SILK_DEBUG << "table: " << table << " key: " << key << " from_key: " << from_key;

    core::rawdb::Walker walker = [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
        SILK_TRACE << "k: " << k << " v: " << v;
        auto chunk = std::make_unique<Roaring>(Roaring::readSafe(reinterpret_cast<const char*>(v.data()), v.size()));
        SILK_TRACE << "chunk: " << chunk->toString();
        chunks.push_back(std::move(chunk));
        auto block = endian::load_big_u32(&k[k.size() - sizeof(uint32_t)]);
        return block < to_block;
    };
    co_await db_reader.walk(table, from_key, gsl::narrow<uint32_t>(key.size() * CHAR_BIT), walker);

    auto result{fast_or(chunks.size(), chunks)};
    SILK_DEBUG << "result: " << result.toString();
    co_return result;
}

Task<Roaring> from_topics(
    core::rawdb::DatabaseReader& db_reader,
    const std::string& table,
    const FilterTopics& topics,
    uint64_t start,
    uint64_t end) {
    SILK_DEBUG << "#topics: " << topics.size() << " start: " << start << " end: " << end;
    roaring::Roaring result_bitmap;
    for (const auto& subtopics : topics) {
        SILK_DEBUG << "#subtopics: " << subtopics.size();
        roaring::Roaring subtopic_bitmap;
        for (auto& topic : subtopics) {
            silkworm::Bytes topic_key{std::begin(topic.bytes), std::end(topic.bytes)};
            SILK_TRACE << "topic: " << silkworm::to_hex(topic) << " topic_key: " << silkworm::to_hex(topic_key);
            auto bitmap = co_await ethdb::bitmap::get(db_reader, table, topic_key, gsl::narrow<uint32_t>(start), gsl::narrow<uint32_t>(end));
            SILK_TRACE << "bitmap: " << bitmap.toString();
            subtopic_bitmap |= bitmap;
            SILK_TRACE << "subtopic_bitmap: " << subtopic_bitmap.toString();
        }
        if (!subtopic_bitmap.isEmpty()) {
            if (result_bitmap.isEmpty()) {
                result_bitmap = subtopic_bitmap;
            } else {
                result_bitmap &= subtopic_bitmap;
            }
        }
        SILK_DEBUG << "result_bitmap: " << result_bitmap.toString();
    }
    co_return result_bitmap;
}

Task<Roaring> from_addresses(
    core::rawdb::DatabaseReader& db_reader,
    const std::string& table,
    const FilterAddresses& addresses,
    uint64_t start,
    uint64_t end) {
    SILK_TRACE << "#addresses: " << addresses.size() << " start: " << start << " end: " << end;
    roaring::Roaring result_bitmap;
    for (auto& address : addresses) {
        silkworm::Bytes address_key{std::begin(address.bytes), std::end(address.bytes)};
        auto bitmap = co_await ethdb::bitmap::get(db_reader, table, address_key, gsl::narrow<uint32_t>(start), gsl::narrow<uint32_t>(end));
        SILK_TRACE << "bitmap: " << bitmap.toString();
        result_bitmap |= bitmap;
    }
    SILK_TRACE << "result_bitmap: " << result_bitmap.toString();
    co_return result_bitmap;
}

}  // namespace silkworm::rpc::ethdb::bitmap
