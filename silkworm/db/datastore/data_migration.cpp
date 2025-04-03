// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "data_migration.hpp"

#include <chrono>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>

namespace silkworm::datastore {

Task<bool> DataMigration::exec() {
    SILK_DEBUG_M(name()) << "START";
    SILK_DEBUG_M(name()) << "pre-cleanup";
    co_await cleanup();
    auto command = next_command();
    if (!command) {
        SILK_DEBUG_M(name()) << "END noop";
        co_return false;
    }
    SILK_DEBUG_M(name()) << "migrate " << command->to_string();
    auto result = migrate(std::move(command));
    SILK_DEBUG_M(name()) << "index";
    index(result);
    SILK_DEBUG_M(name()) << "commit";
    commit(result);
    SILK_DEBUG_M(name()) << "post-cleanup";
    co_await cleanup();
    SILK_DEBUG_M(name()) << "END";
    co_return true;
}

Task<void> DataMigration::run_loop() {
    using namespace std::chrono_literals;
    while (true) {
        bool has_migrated = co_await exec();
        if (!has_migrated) co_await sleep(1min);
    }
}

}  // namespace silkworm::datastore
