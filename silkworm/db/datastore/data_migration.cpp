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

#include "data_migration.hpp"

#include <chrono>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>

namespace silkworm::db {

Task<bool> DataMigration::exec() {
    log::Debug(name()) << "START";
    log::Debug(name()) << "pre-cleanup";
    co_await cleanup();
    auto command = next_command();
    if (!command) {
        log::Debug(name()) << "END noop";
        co_return false;
    }
    log::Debug(name()) << "migrate " << command->description();
    auto result = migrate(std::move(command));
    log::Debug(name()) << "index";
    index(result);
    log::Debug(name()) << "commit";
    commit(result);
    log::Debug(name()) << "post-cleanup";
    co_await cleanup();
    log::Debug(name()) << "END";
    co_return true;
}

Task<void> DataMigration::run_loop() {
    using namespace std::chrono_literals;
    while (true) {
        bool has_migrated = co_await exec();
        if (!has_migrated) co_await sleep(1min);
    }
}

}  // namespace silkworm::db
