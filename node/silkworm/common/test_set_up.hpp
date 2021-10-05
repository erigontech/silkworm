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

#ifndef SILKWORM_COMMON_TEST_SET_UP_HPP_
#define SILKWORM_COMMON_TEST_SET_UP_HPP_

#include <silkworm/common/directories.hpp>
#include <silkworm/db/mdbx.hpp>

namespace silkworm::test {

// SetUp is a helper resource manager for test set-up.
// Upon construction, it creates all the necessary data directories and DB tables.
// SetUp follows the RAII idiom and cleans up its temporary directory upon destruction.
class SetUp {
  public:
    SetUp();

    // Not copyable nor movable
    SetUp(const SetUp&) = delete;
    SetUp& operator=(const SetUp&) = delete;

    [[nodiscard]] const DataDirectory& dir() const { return data_dir_; }

    [[nodiscard]] mdbx::txn& txn() { return txn_; }

  private:
    TemporaryDirectory tmp_dir_;
    DataDirectory data_dir_;
    mdbx::env_managed env_;
    mdbx::txn_managed txn_;
};

}  // namespace silkworm::test

#endif  // SILKWORM_COMMON_TEST_SET_UP_HPP_
