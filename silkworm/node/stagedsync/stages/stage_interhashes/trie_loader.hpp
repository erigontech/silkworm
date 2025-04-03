// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/prefix_set.hpp>
#include <silkworm/db/datastore/etl/collector.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_cursor.hpp>

namespace silkworm::trie {

class TrieLoader {
  public:
    explicit TrieLoader(
        datastore::kvdb::ROTxn& txn,
        PrefixSet* account_changes,
        PrefixSet* storage_changes,
        datastore::etl::Collector* account_trie_node_collector,
        datastore::etl::Collector* storage_trie_node_collector);

    //! \brief (re)calculates root hash on behalf of collected hashed changes and existing data in TrieOfAccount and
    //! TrieOfStorage buckets
    //! \return The computed hash
    //! \remark May throw
    evmc::bytes32 calculate_root();

    //! \brief Returns the hex representation of current load key (for progress tracking)
    std::string get_log_key() const {
        std::scoped_lock lock{log_mtx_};
        return log_key_;
    }

  private:
    datastore::kvdb::ROTxn& txn_;
    PrefixSet* account_changes_;
    PrefixSet* storage_changes_;
    datastore::etl::Collector* account_trie_node_collector_;
    datastore::etl::Collector* storage_trie_node_collector_;

    std::string log_key_{};         // To export logging key
    mutable std::mutex log_mtx_{};  // Guards async logging

    //! \brief (re)calculates storage root hash on behalf of collected hashed changes and existing data in
    //! TrieOfStorage bucket
    //! \return The computed hash
    //! \remark May throw
    static evmc::bytes32 calculate_storage_root(
        TrieCursor& trie_storage_cursor,
        HashBuilder& storage_hash_builder,
        datastore::kvdb::ROCursorDupSort& hashed_storage,
        const Bytes& db_storage_prefix);
};
}  // namespace silkworm::trie
