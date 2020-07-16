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

#include "database.hpp"

#include "bucket.hpp"
#include "history_index.hpp"
#include "types/block.hpp"
#include "util.hpp"

namespace silkworm::db {
std::optional<BlockWithHash> Database::get_block(uint64_t block_number) {
  BlockWithHash bh{};
  auto txn{begin_ro_transaction()};

  auto header_bucket{txn->get_bucket(bucket::kBlockHeader)};
  std::optional<std::string_view> hash_val{header_bucket->get(header_hash_key(block_number))};
  if (!hash_val) return {};

  std::memcpy(bh.hash.bytes, hash_val->data(), kHashLength);
  std::string key{block_key(block_number, bh.hash)};

  std::optional<std::string_view> header_rlp{header_bucket->get(key)};
  if (!header_rlp) return {};

  auto header_stream{as_stream(*header_rlp)};
  rlp::decode(header_stream, bh.block.header);

  auto body_bucket{txn->get_bucket(bucket::kBlockBody)};
  std::optional<std::string_view> body_rlp{body_bucket->get(key)};
  if (!body_rlp) return {};

  auto body_stream{as_stream(*body_rlp)};
  rlp::decode<BlockBody>(body_stream, bh.block);

  return bh;
}

std::vector<evmc::address> Database::get_senders(uint64_t block_number,
                                                 const evmc::bytes32& block_hash) {
  auto txn{begin_ro_transaction()};
  auto bucket{txn->get_bucket(bucket::kSenders)};
  std::vector<evmc::address> senders{};
  std::optional<std::string_view> data{bucket->get(block_key(block_number, block_hash))};
  if (!data) return senders;
  assert(data->length() % kAddressLength == 0);
  senders.resize(data->length() / kAddressLength);
  std::memcpy(senders.data(), data->data(), data->size());
  return senders;
}

std::optional<Account> Database::get_account(const evmc::address& address, uint64_t block_num) {
  auto key{full_view(address)};
  auto txn{begin_ro_transaction()};

  std::optional<std::string_view> encoded{find_in_history(*txn, /*storage=*/false, key, block_num)};
  if (!encoded) {
    auto state_bucket{txn->get_bucket(bucket::kPlainState)};
    encoded = state_bucket->get(key);
  }
  if (!encoded || encoded->empty()) return {};

  std::optional<Account> acc{decode_account_from_storage(*encoded)};

  if (acc && acc->incarnation > 0 && acc->code_hash == kEmptyHash) {
    // restore code hash
    auto code_hash_bucket{txn->get_bucket(bucket::kCodeHash)};
    std::optional<std::string_view> hash{
        code_hash_bucket->get(storage_prefix(address, acc->incarnation))};
    if (hash && hash->length() == kHashLength) {
      std::memcpy(acc->code_hash.bytes, hash->data(), kHashLength);
    }
  }

  return acc;
}

std::string Database::get_code(const evmc::bytes32& code_hash) {
  auto txn{begin_ro_transaction()};
  auto bucket{txn->get_bucket(bucket::kCode)};
  std::optional<std::string_view> val{bucket->get(full_view(code_hash))};
  if (!val) return {};
  return std::string{*val};
}

std::optional<AccountChanges> Database::get_account_changes(uint64_t block_number) {
  auto txn{begin_ro_transaction()};
  auto bucket{txn->get_bucket(bucket::kAccountChanges)};
  std::optional<std::string_view> val{bucket->get(encode_timestamp(block_number))};
  if (!val) return {};
  return AccountChanges::decode(*val);
}

std::string Database::get_storage_changes(uint64_t block_number) {
  auto txn{begin_ro_transaction()};
  auto bucket{txn->get_bucket(bucket::kStorageChanges)};
  std::optional<std::string_view> val{bucket->get(encode_timestamp(block_number))};
  if (!val) return {};
  return std::string{*val};
}

evmc::bytes32 Database::get_storage(const evmc::address& address, uint64_t incarnation,
                                    const evmc::bytes32& key, uint64_t block_number) {
  auto composite_key{storage_key(address, incarnation, key)};
  auto txn{begin_ro_transaction()};
  std::optional<std::string_view> val{
      find_in_history(*txn, /*storage=*/true, composite_key, block_number)};
  if (!val) {
    auto bucket{txn->get_bucket(bucket::kPlainState)};
    val = bucket->get(composite_key);
  }
  if (!val || val->length() != kHashLength) return {};

  evmc::bytes32 res;
  std::memcpy(res.bytes, val->data(), kHashLength);
  return res;
}

std::optional<std::string_view> Database::find_in_history(Transaction& txn, bool storage,
                                                          std::string_view key,
                                                          uint64_t block_number) {
  auto history_name{storage ? bucket::kStorageHistory : bucket::kAccountHistory};
  auto history_bucket{txn.get_bucket(history_name)};
  auto cursor{history_bucket->cursor()};
  std::optional<Entry> entry{cursor->seek(history_index_key(key, block_number))};
  if (!entry) return {};

  std::string_view k{entry->key};
  if (storage) {
    if (k.substr(0, kAddressLength) != key.substr(0, kAddressLength) ||
        k.substr(kAddressLength, kHashLength) != key.substr(kAddressLength + kIncarnationLength)) {
      return {};
    }
  } else if (!k.starts_with(key)) {
    return {};
  }

  std::optional<history_index::SearchResult> res{history_index::find(entry->value, block_number)};
  if (!res) return {};

  if (res->new_record && !storage) return std::string_view{};

  auto change_name{storage ? bucket::kStorageChanges : bucket::kAccountChanges};
  auto change_bucket{txn.get_bucket(change_name)};

  uint64_t change_block{res->change_block};
  std::optional<std::string_view> changes{change_bucket->get(encode_timestamp(change_block))};
  if (!changes) return {};

  if (storage) {
    return StorageChanges::find(*changes, key);
  } else {
    return AccountChanges::find(*changes, key);
  }
}
}  // namespace silkworm::db
