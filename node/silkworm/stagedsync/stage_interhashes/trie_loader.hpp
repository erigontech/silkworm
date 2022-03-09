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

#ifndef SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_LOADER_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_LOADER_HPP_

#include <silkworm/db/mdbx.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/trie/prefix_set.hpp>

namespace silkworm::trie {

// Erigon FlatDBTrieLoader
class DbTrieLoader {
  public:
    DbTrieLoader(const DbTrieLoader&) = delete;
    DbTrieLoader& operator=(const DbTrieLoader&) = delete;

    DbTrieLoader(mdbx::txn& txn, etl::Collector& account_collector, etl::Collector& storage_collector);

    evmc::bytes32 calculate_root(PrefixSet& account_changes, PrefixSet& storage_changes);

  private:
    evmc::bytes32 calculate_storage_root(const Bytes& key_with_inc, PrefixSet& changed);

    mdbx::txn& txn_;
    HashBuilder hb_;
    etl::Collector& storage_collector_;
    Bytes rlp_;
};

}  // namespace silkworm::trie

#endif  // SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_LOADER_HPP_
