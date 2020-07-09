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

#include "reader.hpp"

#include "bucket.hpp"
#include "types/block.hpp"
#include "util.hpp"

namespace silkworm::db {
std::optional<Block> get_block(Database& db, uint64_t block_number) {
  std::unique_ptr<db::Transaction> txn{db.begin_ro_transaction()};
  std::unique_ptr<db::Bucket> header_bucket{txn->get_bucket(db::bucket::kBlockHeader)};
  std::optional<std::string_view> hash_val{header_bucket->get(header_hash_key(block_number))};
  if (!hash_val) return {};
  std::string block_key{encode_block_number(block_number)};
  block_key.append(*hash_val);
  std::optional<std::string_view> header_rlp{header_bucket->get(block_key)};
  if (!header_rlp) return {};
  Block block{};
  auto header_stream{string_view_as_stream(*header_rlp)};
  rlp::decode(header_stream, block.header);
  std::unique_ptr<db::Bucket> body_bucket{txn->get_bucket(db::bucket::kBlockBody)};
  std::optional<std::string_view> body_rlp{body_bucket->get(block_key)};
  if (!body_rlp) return {};
  auto body_stream{string_view_as_stream(*body_rlp)};
  rlp::decode<BlockBody>(body_stream, block);
  return block;
}

std::optional<AccountChanges> get_account_changes(Database& db, uint64_t block_number) {
  std::unique_ptr<db::Transaction> txn{db.begin_ro_transaction()};
  std::unique_ptr<db::Bucket> bucket{txn->get_bucket(db::bucket::kPlainAccountChangeSet)};
  std::optional<std::string_view> val{bucket->get(encode_block_number(block_number))};
  if (!val) return {};
  return decode_account_changes(*val);
}
}  // namespace silkworm::db
