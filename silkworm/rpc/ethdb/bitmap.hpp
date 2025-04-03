// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <roaring/roaring.hh>
#pragma GCC diagnostic pop

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/types/filter.hpp>

namespace silkworm::rpc::ethdb::bitmap {

Task<roaring::Roaring> get(
    db::kv::api::Transaction& tx,
    const std::string& table,
    Bytes& key,
    uint32_t from_block,
    uint32_t to_block);

Task<roaring::Roaring> from_topics(
    db::kv::api::Transaction& tx,
    const std::string& table,
    const FilterTopics& topics,
    uint64_t start,
    uint64_t end);

Task<roaring::Roaring> from_addresses(
    db::kv::api::Transaction& tx,
    const std::string& table,
    const FilterAddresses& addresses,
    uint64_t start,
    uint64_t end);

}  // namespace silkworm::rpc::ethdb::bitmap
