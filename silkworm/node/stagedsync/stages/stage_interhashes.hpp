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
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/etl/collector.hpp>
#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_loader.hpp>

namespace silkworm::stagedsync {

class InterHashes final : public Stage {
  public:
    InterHashes(
        SyncContext* sync_context,
        db::DataModelFactory data_model_factory,
        datastore::etl::CollectorSettings etl_settings)
        : Stage(sync_context, db::stages::kIntermediateHashesKey),
          data_model_factory_(std::move(data_model_factory)),
          etl_settings_(std::move(etl_settings)) {}
    ~InterHashes() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    //! \brief Resets all fields related to log progress tracking
    void reset_log_progress();

    //! \brief See Erigon (p *HashPromoter) Promote
    trie::PrefixSet collect_account_changes(db::RWTxn& txn, BlockNum from, BlockNum to,
                                            absl::btree_map<evmc::address, ethash_hash256>& hashed_addresses);

    //! \brief See Erigon (p *HashPromoter) Promote
    trie::PrefixSet collect_storage_changes(db::RWTxn& txn, BlockNum from, BlockNum to,
                                            absl::btree_map<evmc::address, ethash_hash256>& hashed_addresses);

    //! \brief Erigon RegenerateIntermediateHashes
    //! \remarks might throw WrongRoot
    //! \return the state root
    Stage::Result regenerate_intermediate_hashes(
        db::RWTxn& txn,
        const evmc::bytes32* expected_root = nullptr);

    //! \brief Erigon IncrementIntermediateHashes
    //! \remarks might throw
    //! \return the state root
    [[maybe_unused]] Stage::Result increment_intermediate_hashes(
        db::RWTxn& txn,
        BlockNum from,
        BlockNum to,
        const evmc::bytes32* expected_root = nullptr);

    //! \brief Persists in TrieAccount and TrieStorage the collected nodes (and respective deletions if any)
    void flush_collected_nodes(db::RWTxn& txn);

    /*
    **Theoretically:** "Merkle trie root calculation" starts from state, build from state keys - trie,
    on each level of trie calculates intermediate hash of underlying data.

    **Practically:** It can be implemented as "Preorder trie traversal" (Preorder - visit Root, visit Left, visit
    Right). But, let's make couple observations to make traversal over huge state efficient.

    **Observation 1:** `TrieOfAccounts` already stores state keys in sorted way.
    Iteration over this bucket will retrieve keys in same order as "Preorder trie traversal".

    **Observation 2:** each Eth block - changes not big part of state - it means most of Merkle trie intermediate hashes
    will not change. It means we effectively can cache them. `TrieOfAccounts` stores "Intermediate hashes of all Merkle
    trie levels". It also sorted and Iteration over `TrieOfAccounts` will retrieve keys in same order as "Preorder trie
    traversal".

    **Implementation:** by opening 1 Cursor on state and 1 more Cursor on intermediate hashes bucket - we will receive
    data in order of "Preorder trie traversal". Cursors will only do "sequential reads" and "jumps forward" - been
    hardware-friendly.

    Imagine that account with key 0000....00 (64 zeroes, 32 bytes of zeroes) changed.
    Here is an example sequence which can be seen by running 2 Cursors:
    ```
    00                   // key came from cache, can't use it - because account with this prefix changed
    0000                 // key came from cache, can't use it - because account with this prefix changed
    ...
    {30 zero bytes}00    // key which came from cache, can't use it - because account with this prefix changed
    {30 zero bytes}0000  // account came from state, use it - calculate hash, jump to next sub-trie
    {30 zero bytes}01    // key came from cache, it's next sub-trie, use it, jump to next sub-trie
    {30 zero bytes}02    // key came from cache, it's next sub-trie, use it, jump to next sub-trie
    ...
    {30 zero bytes}ff    // key came from cache, it's next sub-trie, use it, jump to next sub-trie
    {29 zero bytes}01    // key came from cache, it's next sub-trie (1 byte shorter key), use it, jump to next sub-trie
    {29 zero bytes}02    // key came from cache, it's next sub-trie (1 byte shorter key), use it, jump to next sub-trie
    ...
    ff                   // key came from cache, it's next sub-trie (1 byte shorter key), use it, jump to next sub-trie
    nil                  // db returned nil - means no more keys there, done
    ```
    In practice Trie is not full - it means that after account key `{30 zero bytes}0000` may come `{5 zero bytes}01` and
    amount of iterations will not be big.
    */

    // The loader which (re)builds the trees
    std::unique_ptr<trie::TrieLoader> trie_loader_;

    db::DataModelFactory data_model_factory_;

    datastore::etl::CollectorSettings etl_settings_;

    std::unique_ptr<datastore::kvdb::Collector> account_collector_;  // To accumulate new records for kTrieOfAccounts
    std::unique_ptr<datastore::kvdb::Collector> storage_collector_;  // To accumulate new records for kTrieOfStorage
    std::unique_ptr<datastore::kvdb::Collector> loading_collector_;  // Effectively the current collector undergoing load (for log)

    // Logger info
    std::mutex log_mtx_{};                 // Guards async logging
    std::atomic_bool incremental_{false};  // Whether operation is incremental
    std::atomic_bool loading_{false};      // Whether we're etl loading
    std::string current_source_;           // Current source of data
    std::string current_target_;           // Current target of data
    std::string current_key_;              // Actual processing key
};

}  // namespace silkworm::stagedsync
