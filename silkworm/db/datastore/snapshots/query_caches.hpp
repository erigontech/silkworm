// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>

#include "../common/entity_name.hpp"
#include "query_caches_schema.hpp"

namespace silkworm::snapshots {

class QueryCaches {
  public:
    explicit QueryCaches(
        QueryCachesSchema schema,
        const std::filesystem::path& snapshots_path,
        std::optional<uint32_t> index_salt = std::nullopt)
        : schema_{std::move(schema)} {
        index_salt_ = index_salt ? index_salt : load_index_salt(snapshots_path);
        register_caches(schema_);
    }

    template <class TCache>
    std::shared_ptr<TCache> cache(datastore::EntityName query_name, datastore::EntityName entity_name) const {
        if (caches_.contains(query_name)) {
            auto& caches = caches_.at(query_name);
            if (caches.contains(entity_name)) {
                std::shared_ptr<void> cache = caches.at(entity_name);
                return std::static_pointer_cast<TCache>(std::move(cache));
            }
        }
        return {};
    }

  private:
    template <class TCache>
    void add_cache(datastore::EntityName query_name, datastore::EntityName entity_name, std::shared_ptr<TCache> cache) {
        caches_.try_emplace(query_name, decltype(caches_)::mapped_type{});
        caches_.at(query_name).emplace(entity_name, std::shared_ptr<void>{cache});
    }

    template <class TCache>
    void register_caches(const QueryCachesSchema& schema, datastore::EntityName query_name, std::function<std::shared_ptr<TCache>(size_t)> cache_factory) {
        size_t cache_size = schema.cache_size(query_name);
        for (auto& [entity_name, _] : schema.entities()) {
            add_cache<TCache>(query_name, entity_name, cache_factory(cache_size));
        }
    }

    void register_caches(const QueryCachesSchema& schema);

    std::optional<uint32_t> load_index_salt(const std::filesystem::path& snapshots_path) const;

    QueryCachesSchema schema_;
    std::optional<uint32_t> index_salt_;
    datastore::EntityMap<datastore::EntityMap<std::shared_ptr<void>>> caches_;
};

}  // namespace silkworm::snapshots
