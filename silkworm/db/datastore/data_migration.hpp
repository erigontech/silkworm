// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include "data_migration_command.hpp"

namespace silkworm::datastore {

struct DataMigrationResult {
    virtual ~DataMigrationResult() = default;
};

struct DataMigration {
    virtual ~DataMigration() = default;

    Task<bool> exec();
    Task<void> run_loop();

  protected:
    virtual const char* name() const = 0;
    virtual std::unique_ptr<DataMigrationCommand> next_command() = 0;
    virtual std::shared_ptr<DataMigrationResult> migrate(std::unique_ptr<DataMigrationCommand> command) = 0;
    virtual void index(std::shared_ptr<DataMigrationResult> result) = 0;
    virtual void commit(std::shared_ptr<DataMigrationResult> result) = 0;
    virtual Task<void> cleanup() = 0;
};

}  // namespace silkworm::datastore
