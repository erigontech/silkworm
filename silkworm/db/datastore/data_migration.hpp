/*
   Copyright 2024 The Silkworm Authors

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
