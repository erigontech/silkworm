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
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/types/filter.hpp>

namespace silkworm::rpc::ethdb::bitmap {

Task<roaring::Roaring> get(
    core::rawdb::DatabaseReader& db_reader,
    const std::string& table,
    silkworm::Bytes& key,
    uint32_t from_block,
    uint32_t to_block);

Task<roaring::Roaring> from_topics(
    core::rawdb::DatabaseReader& db_reader,
    const std::string& table,
    const FilterTopics& topics,
    uint64_t start,
    uint64_t end);

Task<roaring::Roaring> from_addresses(
    core::rawdb::DatabaseReader& db_reader,
    const std::string& table,
    const FilterAddresses& addresses,
    uint64_t start,
    uint64_t end);

}  // namespace silkworm::rpc::ethdb::bitmap
