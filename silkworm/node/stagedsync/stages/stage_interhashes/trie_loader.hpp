/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/prefix_set.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/node/etl/collector.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_cursor.hpp>

namespace silkworm::trie {

class TrieLoader {
  public:
    explicit TrieLoader(db::ROTxn& txn, PrefixSet* account_changes, PrefixSet* storage_changes,
                        etl::Collector* account_trie_node_collector, etl::Collector* storage_trie_node_collector);

    //! \brief (re)calculates root hash on behalf of collected hashed changes and existing data in TrieOfAccount and
    //! TrieOfStorage buckets
    //! \return The computed hash
    //! \remark May throw
    [[nodiscard]] evmc::bytes32 calculate_root();

    //! \brief Returns the hex representation of current load key (for progress tracking)
    [[nodiscard]] std::string get_log_key() const {
        std::unique_lock lock{log_mtx_};
        return log_key_;
    }

  private:
    db::ROTxn& txn_;
    PrefixSet* account_changes_;
    PrefixSet* storage_changes_;
    etl::Collector* account_trie_node_collector_;
    etl::Collector* storage_trie_node_collector_;

    std::string log_key_{};         // To export logging key
    mutable std::mutex log_mtx_{};  // Guards async logging

    //! \brief (re)calculates storage root hash on behalf of collected hashed changes and existing data in
    //! TrieOfStorage bucket
    //! \return The computed hash
    //! \remark May throw
    [[nodiscard]] static evmc::bytes32 calculate_storage_root(TrieCursor& trie_storage_cursor,
                                                              HashBuilder& storage_hash_builder,
                                                              db::ROCursorDupSort& hashed_storage,
                                                              const Bytes& db_storage_prefix);
};
}  // namespace silkworm::trie
