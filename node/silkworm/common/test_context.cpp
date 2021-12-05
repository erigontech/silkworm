/*
   Copyright 2021 The Silkworm Authors

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

#include "test_context.hpp"

#include <silkworm/db/tables.hpp>

namespace silkworm::test {

Context::Context(bool with_create_tables) : tmp_dir_{}, data_dir_{tmp_dir_.path()} {
    data_dir_.deploy();

    db::EnvConfig config{data_dir_.chaindata().path().string(), /*create=*/true};
    config.inmemory = true;

    env_ = db::open_env(config);
    txn_ = env_.start_write();
    if (with_create_tables) {
        db::table::check_or_create_chaindata_tables(txn_);
    }
}

}  // namespace silkworm::test
