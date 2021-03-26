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

#ifndef SILKWORM_TRIE_DB_TRIE_HPP_
#define SILKWORM_TRIE_DB_TRIE_HPP_

#include <optional>
#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {

struct Node {
    uint16_t state_mask{0};
    uint16_t tree_mask{0};
    uint16_t hash_mask{0};

    std::vector<evmc::bytes32> hashes{};
};

// TG RootHashAggregator
class Aggregator {
  public:
    Aggregator(const Aggregator&) = delete;
    Aggregator& operator=(const Aggregator&) = delete;

    Aggregator() = default;

    void add_account(const Account& account);

    void cut_off();

    evmc::bytes32 root() const;
};

// TG AccTrieCursor
class AccountTrieCursor {
  public:
    AccountTrieCursor(const AccountTrieCursor&) = delete;
    AccountTrieCursor& operator=(const AccountTrieCursor&) = delete;

    AccountTrieCursor(lmdb::Transaction& txn, etl::Collector& account_collector);

    bool can_skip_state() const;

    Bytes first_uncovered_prefix() const;

    std::optional<Bytes> key() const;

    void next();
};

// TG FlatDBTrieLoader
class DbTrieLoader {
  public:
    DbTrieLoader(const DbTrieLoader&) = delete;
    DbTrieLoader& operator=(const DbTrieLoader&) = delete;

    DbTrieLoader(lmdb::Transaction& txn, etl::Collector& account_collector);

    evmc::bytes32 calculate_root();

  private:
    lmdb::Transaction& txn_;
    etl::Collector& account_collector_;
    Aggregator aggregator_;
};

class WrongRoot : public std::runtime_error {
  public:
    WrongRoot() : std::runtime_error{"wrong trie root"} {}
};

// TG UnmarshalTrieNode
Node unmarshal_node(ByteView v);

// TG RegenerateIntermediateHashes
// might throw WrongRoot
void regenerate_db_tries(lmdb::Transaction& txn, const char* tmp_dir, evmc::bytes32* expected_root = nullptr);

}  // namespace silkworm::trie

#endif  // SILKWORM_TRIE_DB_TRIE_HPP_
