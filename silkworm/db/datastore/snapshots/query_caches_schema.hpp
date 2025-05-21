// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "../common/entity_name.hpp"

namespace silkworm::snapshots {

class QueryCachesSchema {
  public:
    QueryCachesSchema& enable(datastore::EntityName entity_name) {
        entities_[entity_name] = true;
        return *this;
    }

    QueryCachesSchema& cache_size(datastore::EntityName query_name, size_t size) {
        cache_sizes_[query_name] = size;
        return *this;
    }

    QueryCachesSchema& index_salt_file_name(std::string_view value) {
        index_salt_file_name_ = value;
        return *this;
    }

    const datastore::EntityMap<bool>& entities() const { return entities_; }
    bool is_enabled(datastore::EntityName entity_name) const { return entities_.contains(entity_name); }
    size_t cache_size(datastore::EntityName query_name) const { return cache_sizes_.at(query_name); }
    const std::string& index_salt_file_name() const { return index_salt_file_name_.value(); }

  private:
    datastore::EntityMap<bool> entities_;
    datastore::EntityMap<size_t> cache_sizes_;
    std::optional<std::string> index_salt_file_name_;
};

}  // namespace silkworm::snapshots
