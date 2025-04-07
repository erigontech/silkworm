// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <string>

#include "../common/entity_name.hpp"

namespace silkworm::datastore::kvdb {

class Schema {
  public:
    class TableDef {
      public:
        TableDef& name(std::string_view name) {
            name_ = name;
            return *this;
        }

        TableDef& enable_multi_value() {
            is_multi_value_ = true;
            return *this;
        }

        TableDef& disable_multi_value() {
            is_multi_value_ = false;
            return *this;
        }

        const std::string& name() const { return name_.value(); }
        bool is_multi_value() const { return is_multi_value_; }

      private:
        std::optional<std::string> name_;
        bool is_multi_value_{false};
    };

    class EntityDef {
      public:
        virtual ~EntityDef() = default;

        TableDef& table(datastore::EntityName name) {
            return table_defs_[name];
        }

        EntityDef& undefine(datastore::EntityName name) {
            table_defs_.erase(name);
            return *this;
        }

        const EntityMap<TableDef>& tables() const { return table_defs_; }

      private:
        EntityMap<TableDef> table_defs_;
    };

    class DomainDef : public EntityDef {
      public:
        ~DomainDef() override = default;

        DomainDef& values_disable_multi_value() {
            table(kDomainValuesName).disable_multi_value();
            table(kHistoryValuesName).disable_multi_value();
            return *this;
        }

        DomainDef& enable_large_values() {
            has_large_values_ = true;
            return *this;
        }

        DomainDef& without_history() {
            DatabaseDef::undefine_history_schema(*this);
            return *this;
        }

        bool has_large_values() const { return has_large_values_; }

      private:
        bool has_large_values_{false};
    };

    class DatabaseDef {
      public:
        EntityDef& default_entity() {
            entity_defs_.try_emplace(kDefaultEntityName, std::make_shared<EntityDef>());
            return *entity_defs_.at(kDefaultEntityName);
        }

        DomainDef& domain(datastore::EntityName name) {
            entity_defs_.try_emplace(name, std::make_shared<DomainDef>(make_domain_schema(name)));
            return dynamic_cast<DomainDef&>(*entity_defs_.at(name));
        }

        EntityDef& inverted_index(datastore::EntityName name) {
            entity_defs_.try_emplace(name, std::make_shared<EntityDef>(make_inverted_index_schema(name)));
            return *entity_defs_.at(name);
        }

        const EntityMap<std::shared_ptr<EntityDef>>& entities() const { return entity_defs_; }

      private:
        friend DomainDef;
        static DomainDef make_domain_schema(datastore::EntityName name);
        static EntityDef make_history_schema(datastore::EntityName name);
        static void define_history_schema(datastore::EntityName name, EntityDef& schema);
        static void undefine_history_schema(EntityDef& schema);
        static EntityDef make_inverted_index_schema(datastore::EntityName name);
        static void define_inverted_index_schema(datastore::EntityName name, EntityDef& schema);
        static void undefine_inverted_index_schema(EntityDef& schema);

        EntityMap<std::shared_ptr<EntityDef>> entity_defs_;
    };

    DatabaseDef& database(datastore::EntityName name) {
        return database_defs_[name];
    }

    DatabaseDef& default_database() {
        return database(kDefaultEntityName);
    }

    static inline const datastore::EntityName kDefaultEntityName{"_"};

    static inline const datastore::EntityName kDomainValuesName{"DomainValues"};
    static inline const datastore::EntityName kHistoryValuesName{"HistoryValues"};
    static inline const datastore::EntityName kInvIdxKeysName{"InvIdxKeys"};
    static inline const datastore::EntityName kInvIdxIndexName{"InvIdxIndex"};

  private:
    EntityMap<DatabaseDef> database_defs_;
};

}  // namespace silkworm::datastore::kvdb
