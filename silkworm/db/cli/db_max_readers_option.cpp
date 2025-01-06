/*
   Copyright 2023 The Silkworm Authors

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

#include "db_max_readers_option.hpp"

#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::cmd::common {

void add_option_db_max_readers(CLI::App& cli, uint32_t& max_readers) {
    cli.add_option("--mdbx.max.readers", max_readers, "The maximum number of MDBX readers")
        ->default_val(silkworm::datastore::kvdb::EnvConfig{}.max_readers)
        ->check(CLI::Range(1, 32767));
}

}  // namespace silkworm::cmd::common
