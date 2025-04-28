// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "query_caches.hpp"

#include <silkworm/core/common/random_number.hpp>

#include "domain_get_latest_query.hpp"
#include "index_salt_file.hpp"
#include "inverted_index_seek_query.hpp"

namespace silkworm::snapshots {

void QueryCaches::register_caches(const QueryCachesSchema& schema) {
    uint32_t salt = index_salt_.value_or(RandomNumber{}.generate_one());
    KeyHasher key_hasher{salt};

    register_caches(
        schema,
        DomainGetLatestQueryRawWithCache::kName,
        std::function{[key_hasher](size_t cache_size) {
            return std::make_shared<DomainGetLatestQueryRawWithCache::CacheType>(cache_size, key_hasher);
        }});

    register_caches(
        schema,
        InvertedIndexSeekQueryRawWithCache::kName,
        std::function{[key_hasher](size_t cache_size) {
            return std::make_shared<InvertedIndexSeekQueryRawWithCache::CacheType>(cache_size, key_hasher);
        }});
}

std::optional<uint32_t> QueryCaches::load_index_salt(const std::filesystem::path& snapshots_path) const {
    IndexSaltFile file{snapshots_path / schema_.index_salt_file_name()};
    return file.exists() ? file.load() : std::optional<uint32_t>{};
}

}  // namespace silkworm::snapshots
