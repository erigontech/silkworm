// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <vector>

#include <silkworm/infra/common/directories.hpp>

#include "../common/ranges/vector_from_range.hpp"
#include "database.hpp"
#include "domain.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

// by default has_large_values = false, is_multi_value = true
using DomainDefault = std::identity;

struct DomainWithLargeValues {
    Schema::DomainDef& operator()(Schema::DomainDef& domain) const {
        domain.enable_large_values().values_disable_multi_value();
        return domain;
    }
};

enum class EntityKind {
    kDomain,
    kHistory,
    kInvertedIndex,
};

class QueryTest {
  public:
    QueryTest(EntityName name, Schema::DatabaseDef schema)
        : name_{name},
          db_{
              open_env(EnvConfig{.path = tmp_dir_.path().string(), .create = true, .in_memory = true}),
              std::move(schema),
          } {
        db_.create_tables();
    }

    Domain domain() const { return db_.domain(name_); }
    History history() const { return *domain().history; }
    InvertedIndex inverted_index() const { return domain().history->inverted_index; }

    ROAccess access_ro() const { return db_.access_ro(); }
    RWAccess access_rw() const { return db_.access_rw(); }

    template <std::invocable<Schema::DomainDef&> TDomainConfig>
    static Schema::DatabaseDef make_schema(EntityName name) {
        Schema::DatabaseDef schema;
        TDomainConfig domain_config;
        [[maybe_unused]] auto _ = domain_config(schema.domain(name));
        return schema;
    }

    template <std::invocable<Schema::DomainDef&> TDomainConfig>
    static QueryTest make(EntityName name = EntityName{"Test"}) {
        return QueryTest{name, make_schema<TDomainConfig>(name)};
    }

    template <EntityKind kEntityKind, class TEntry, class TEntryQuery, class TResultQuery, typename... TArgs>
    auto find_in(const std::vector<TEntry>& data, TArgs&&... args) {
        auto entity = this->entity<kEntityKind>();
        RWAccess db_access = this->access_rw();

        {
            RWTxnManaged tx = db_access.start_rw_tx();
            TEntryQuery query{tx, entity};
            for (auto& entry : data) {
                auto& [key, value, ts] = entry;
                query.exec(key, value, ts);
            }
            tx.commit_and_stop();
        }

        ROTxnManaged tx = db_access.start_ro_tx();
        TResultQuery query{tx, entity};
        auto results = query.exec(std::forward<TArgs>(args)...);

        if constexpr (std::ranges::input_range<decltype(results)>) {
            return vector_from_range(std::move(results));
        } else {
            return results;
        }
    }

  private:
    template <EntityKind kKind>
    auto entity() {
        if constexpr (kKind == EntityKind::kDomain) {
            return domain();
        }
        if constexpr (kKind == EntityKind::kHistory) {
            return history();
        }
        if constexpr (kKind == EntityKind::kInvertedIndex) {
            return inverted_index();
        }
        std::abort();
    }

    TemporaryDirectory tmp_dir_;
    EntityName name_;
    Database db_;
};

}  // namespace silkworm::datastore::kvdb
