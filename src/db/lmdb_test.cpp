/*
   Copyright 2020 The Silkworm Authors

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

#include "lmdb.hpp"

#include <catch2/catch.hpp>

namespace silkworm::db {

TEST_CASE("LMDB basics") {
  auto bucketName{"PLAIN-CST"};
  auto key{"b1a4F4f387732B107D4F8e8816058bAB6D16397b"};
  auto val{"abba"};

  TemporaryLmdbDatabase db;
  auto txn = db.begin_ro_transaction();

  // TODO(Andrew) get rid of lmdbx and CHECK_THROWS_MATCHES against our own
  // expections
  CHECK_THROWS(txn->create_bucket(bucketName));

  txn = db.begin_rw_transaction();
  CHECK_THROWS(txn->get_bucket(bucketName));

  auto bucket = txn->create_bucket(bucketName);
  CHECK(!bucket->get(key).has_value());

  bucket->put(key, val);
  CHECK(bucket->get(key) == val);
}

}  // namespace silkworm::db
