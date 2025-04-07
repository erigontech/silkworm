// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bitmap.hpp"

#include <climits>
#include <memory>
#include <utility>
#include <vector>

#include <gsl/narrow>

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/ethdb/walk.hpp>

namespace silkworm::rpc::ethdb::bitmap {

using roaring_bitmap_t = roaring::api::roaring_bitmap_t;
using Roaring = roaring::Roaring;
using rpc::ethdb::walk;

static Roaring fast_or(size_t n, const std::vector<std::unique_ptr<Roaring>>& inputs) {
    std::vector<const roaring_bitmap_t*> x(n);
    for (size_t k = 0; k < n; ++k) {
        x[k] = &inputs[k]->roaring;
    }

    roaring_bitmap_t* c_ans = roaring_bitmap_or_many(n, x.data());
    if (c_ans == nullptr) {
        throw std::runtime_error("failed memory alloc in fast_or");
    }
    Roaring ans(c_ans);
    return ans;
}

Task<Roaring> get(
    db::kv::api::Transaction& tx,
    const std::string& table,
    Bytes& key,
    uint32_t from_block,
    uint32_t to_block) {
    std::vector<std::unique_ptr<Roaring>> chunks;

    Bytes from_key{key.begin(), key.end()};
    from_key.resize(key.size() + sizeof(uint32_t));
    endian::store_big_u32(&from_key[key.size()], from_block);
    SILK_DEBUG << "table: " << table << " key: " << key << " from_key: " << from_key;

    auto walker = [&](const Bytes& k, const Bytes& v) {
        SILK_TRACE << "k: " << k << " v: " << v;
        auto chunk = std::make_unique<Roaring>(Roaring::readSafe(reinterpret_cast<const char*>(v.data()), v.size()));
        SILK_TRACE << "chunk: " << chunk->toString();
        chunks.push_back(std::move(chunk));
        auto block = endian::load_big_u32(&k[k.size() - sizeof(uint32_t)]);
        return block < to_block;
    };
    co_await walk(tx, table, from_key, gsl::narrow<uint32_t>(key.size() * CHAR_BIT), walker);

    auto result{fast_or(chunks.size(), chunks)};
    SILK_DEBUG << "result: " << result.toString();
    co_return result;
}

Task<Roaring> from_topics(
    db::kv::api::Transaction& tx,
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
            Bytes topic_key{std::begin(topic.bytes), std::end(topic.bytes)};
            SILK_TRACE << "topic: " << to_hex(topic) << " topic_key: " << to_hex(topic_key);
            auto bitmap = co_await ethdb::bitmap::get(tx, table, topic_key, gsl::narrow<uint32_t>(start), gsl::narrow<uint32_t>(end));
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
    db::kv::api::Transaction& tx,
    const std::string& table,
    const FilterAddresses& addresses,
    uint64_t start,
    uint64_t end) {
    SILK_TRACE << "#addresses: " << addresses.size() << " start: " << start << " end: " << end;
    roaring::Roaring result_bitmap;
    for (auto& address : addresses) {
        Bytes address_key{std::begin(address.bytes), std::end(address.bytes)};
        auto bitmap = co_await ethdb::bitmap::get(tx, table, address_key, gsl::narrow<uint32_t>(start), gsl::narrow<uint32_t>(end));
        SILK_TRACE << "bitmap: " << bitmap.toString();
        result_bitmap |= bitmap;
    }
    SILK_TRACE << "result_bitmap: " << result_bitmap.toString();
    co_return result_bitmap;
}

}  // namespace silkworm::rpc::ethdb::bitmap
