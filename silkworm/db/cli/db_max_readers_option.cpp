// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "db_max_readers_option.hpp"

#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::cmd::common {

void add_option_db_max_readers(CLI::App& cli, uint32_t& max_readers) {
    cli.add_option("--mdbx.max.readers", max_readers, "The maximum number of MDBX readers")
        ->default_val(silkworm::datastore::kvdb::EnvConfig{}.max_readers)
        ->check(CLI::Range(1, 32767));
}

}  // namespace silkworm::cmd::common
