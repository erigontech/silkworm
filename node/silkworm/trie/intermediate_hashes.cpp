/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "intermediate_hashes.hpp"

#include <bitset>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::trie {

Cursor::Cursor(mdbx::cursor& cursor, PrefixSet& changed, ByteView prefix)
    : cursor_{cursor}, changed_{changed}, prefix_{prefix} {
    consume_node(/*key=*/{}, /*exact=*/true);
}

void Cursor::consume_node(ByteView to, bool exact) {
    const Bytes db_key{prefix_ + Bytes{to}};
    const auto entry{exact ? cursor_.find(db::to_slice(db_key), /*throw_notfound=*/false)
                           : cursor_.lower_bound(db::to_slice(db_key), /*throw_notfound=*/false)};

    if (!entry && !exact) {
        // end-of-tree
        stack_.clear();
        return;
    }

    ByteView key = to;
    if (!exact) {
        key = db::from_slice(entry.key);
        if (!has_prefix(key, prefix_)) {
            stack_.clear();
            return;
        }
        key.remove_prefix(prefix_.length());
    }

    std::optional<Node> node{std::nullopt};
    if (entry) {
        node = unmarshal_node(db::from_slice(entry.value));
        SILKWORM_ASSERT(node.has_value());
        SILKWORM_ASSERT(node->state_mask() != 0);
    }

    int nibble{0};
    if (!node.has_value() || node->root_hash().has_value()) {
        nibble = -1;
    } else {
        while ((node->state_mask() & (1u << nibble)) == 0) {
            ++nibble;
        }
    }

    if (!key.empty() && !stack_.empty()) {
        // the root might have nullopt node and thus no state bits, so we rely on the DB
        stack_[0].nibble = key[0];
    }

    stack_.push_back(SubNode{Bytes{key}, node, nibble});

    update_skip_state();

    // don't erase nodes with valid root hashes
    if (entry && (!can_skip_state_ || nibble != -1)) {
        cursor_.erase();
    }
}

void Cursor::next() {
    if (stack_.empty()) {
        // end-of-tree
        return;
    }

    if (!can_skip_state_ && children_are_in_trie()) {
        // go to the child node
        SubNode& sn{stack_.back()};
        if (sn.nibble < 0) {
            move_to_next_sibling(/*allow_root_to_child_nibble_within_subnode=*/true);
        } else {
            consume_node(*key(), /*exact=*/false);
        }
    } else {
        move_to_next_sibling(/*allow_root_to_child_nibble_within_subnode=*/false);
    }

    update_skip_state();
}

void Cursor::update_skip_state() {
    const std::optional<Bytes> k{key()};
    if (k == std::nullopt || changed_.contains(prefix_ + *k)) {
        can_skip_state_ = false;
    } else {
        can_skip_state_ = stack_.back().hash_flag();
    }
}

void Cursor::move_to_next_sibling(bool allow_root_to_child_nibble_within_subnode) {
    if (stack_.empty()) {
        // end-of-tree
        return;
    }

    SubNode& sn{stack_.back()};

    if (sn.nibble >= 15 || (sn.nibble < 0 && !allow_root_to_child_nibble_within_subnode)) {
        // this node is fully traversed
        stack_.pop_back();
        move_to_next_sibling(false);  // on parent
        return;
    }

    ++sn.nibble;

    if (!sn.node.has_value()) {
        // we can't rely on the state flag, so search in the DB
        consume_node(*key(), /*exact=*/false);
        return;
    }

    for (; sn.nibble < 16; ++sn.nibble) {
        if (sn.state_flag()) {
            return;
        }
    }

    // this node is fully traversed
    stack_.pop_back();
    move_to_next_sibling(false);  // on parent
}

Bytes Cursor::SubNode::full_key() const {
    Bytes out{key};
    if (nibble >= 0) {
        out.push_back(nibble);
    }
    return out;
}

bool Cursor::SubNode::state_flag() const {
    if (nibble < 0 || !node.has_value()) {
        return true;
    }
    return node->state_mask() & (1u << nibble);
}

bool Cursor::SubNode::tree_flag() const {
    if (nibble < 0 || !node.has_value()) {
        return true;
    }
    return node->tree_mask() & (1u << nibble);
}

bool Cursor::SubNode::hash_flag() const {
    if (!node.has_value()) {
        return false;
    } else if (nibble < 0) {
        return node->root_hash().has_value();
    }
    return node->hash_mask() & (1u << nibble);
}

const evmc::bytes32* Cursor::SubNode::hash() const {
    if (!hash_flag()) {
        return nullptr;
    }

    if (nibble < 0) {
        return &node->root_hash().value();
    }

    const unsigned first_nibbles_mask{(1u << nibble) - 1};
    const size_t hash_idx{std::bitset<16>(node->hash_mask() & first_nibbles_mask).count()};
    return &node->hashes()[hash_idx];
}

std::optional<Bytes> Cursor::key() const {
    if (stack_.empty()) {
        return std::nullopt;
    }
    return stack_.back().full_key();
}

const evmc::bytes32* Cursor::hash() const {
    if (stack_.empty()) {
        return nullptr;
    }
    return stack_.back().hash();
}

bool Cursor::children_are_in_trie() const {
    if (stack_.empty()) {
        return false;
    }
    return stack_.back().tree_flag();
}

std::optional<Bytes> Cursor::first_uncovered_prefix() const {
    std::optional<Bytes> k{key()};
    if (can_skip_state_ && k != std::nullopt) {
        k = increment_key(*k);
    }
    if (k == std::nullopt) {
        return std::nullopt;
    }
    return pack_nibbles(*k);
}

DbTrieLoader::DbTrieLoader(mdbx::txn& txn, etl::Collector& account_collector, etl::Collector& storage_collector)
    : txn_{txn}, storage_collector_{storage_collector} {
    hb_.node_collector = [&account_collector](ByteView unpacked_key, const Node& node) {
        if (unpacked_key.empty()) {
            return;
        }

        etl::Entry e;
        e.key = unpacked_key;
        e.value = marshal_node(node);

        account_collector.collect(std::move(e));
    };
}

/*
**Theoretically:** "Merkle trie root calculation" starts from state, build from state keys - trie,
on each level of trie calculates intermediate hash of underlying data.

**Practically:** It can be implemented as "Preorder trie traversal" (Preorder - visit Root, visit Left, visit Right).
But, let's make couple observations to make traversal over huge state efficient.

**Observation 1:** `TrieOfAccounts` already stores state keys in sorted way.
Iteration over this bucket will retrieve keys in same order as "Preorder trie traversal".

**Observation 2:** each Eth block - changes not big part of state - it means most of Merkle trie intermediate hashes
will not change. It means we effectively can cache them. `TrieOfAccounts` stores "Intermediate hashes of all Merkle trie
levels". It also sorted and Iteration over `TrieOfAccounts` will retrieve keys in same order as "Preorder trie
traversal".

**Implementation:** by opening 1 Cursor on state and 1 more Cursor on intermediate hashes bucket - we will receive data
in order of "Preorder trie traversal". Cursors will only do "sequential reads" and "jumps forward" - been
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
evmc::bytes32 DbTrieLoader::calculate_root(PrefixSet& account_changes, PrefixSet& storage_changes) {
    auto state{db::open_cursor(txn_, db::table::kHashedAccounts)};
    auto trie_db_cursor{db::open_cursor(txn_, db::table::kTrieOfAccounts)};

    for (Cursor trie{trie_db_cursor, account_changes}; trie.key().has_value();) {
        if (trie.can_skip_state()) {
            SILKWORM_ASSERT(trie.hash() != nullptr);
            hb_.add_branch_node(*trie.key(), *trie.hash(), trie.children_are_in_trie());
        }

        const std::optional<Bytes> uncovered{trie.first_uncovered_prefix()};
        if (uncovered == std::nullopt) {
            // no more uncovered accounts
            break;
        }

        trie.next();

        for (auto acc{state.lower_bound(db::to_slice(*uncovered), /*throw_notfound=*/false)}; acc;
             acc = state.to_next(/*throw_notfound=*/false)) {
            const Bytes unpacked_key{unpack_nibbles(db::from_slice(acc.key))};
            if (trie.key().has_value() && trie.key().value() < unpacked_key) {
                break;
            }
            const auto [account, err]{Account::from_encoded_storage(db::from_slice(acc.value))};
            rlp::success_or_throw(err);

            evmc::bytes32 storage_root{kEmptyRoot};

            if (account.incarnation) {
                const Bytes key_with_inc{db::storage_prefix(db::from_slice(acc.key), account.incarnation)};
                storage_root = calculate_storage_root(key_with_inc, storage_changes);
            }

            hb_.add_leaf(unpacked_key, account.rlp(storage_root));
        }
    }

    return hb_.root_hash();
}

evmc::bytes32 DbTrieLoader::calculate_storage_root(const Bytes& key_with_inc, PrefixSet& changed) {
    auto state{db::open_cursor(txn_, db::table::kHashedStorage)};
    auto trie_db_cursor{db::open_cursor(txn_, db::table::kTrieOfStorage)};

    HashBuilder hb;
    hb.node_collector = [&](ByteView unpacked_storage_key, const Node& node) {
        etl::Entry e{key_with_inc, marshal_node(node)};
        e.key.append(unpacked_storage_key);
        storage_collector_.collect(std::move(e));
    };

    for (Cursor trie{trie_db_cursor, changed, key_with_inc}; trie.key().has_value();) {
        if (trie.can_skip_state()) {
            SILKWORM_ASSERT(trie.hash() != nullptr);
            hb.add_branch_node(*trie.key(), *trie.hash(), trie.children_are_in_trie());
        }

        const std::optional<Bytes> uncovered{trie.first_uncovered_prefix()};
        if (uncovered == std::nullopt) {
            // no more uncovered storage
            break;
        }

        trie.next();

        // TODO (Andrew) consider replacing with cursor_for_each(_multi?)
        for (auto storage{state.lower_bound_multivalue(db::to_slice(key_with_inc), db::to_slice(*uncovered),
                                                       /*throw_notfound=*/false)};
             storage; storage = state.to_current_next_multi(/*throw_notfound=*/false)) {
            const Bytes unpacked_loc{unpack_nibbles(db::from_slice(storage.value).substr(0, kHashLength))};
            if (trie.key().has_value() && trie.key().value() < unpacked_loc) {
                break;
            }

            const ByteView value{db::from_slice(storage.value).substr(kHashLength)};
            rlp_.clear();
            rlp::encode(rlp_, value);
            hb.add_leaf(unpacked_loc, rlp_);
        }
    }

    return hb.root_hash();
}

static evmc::bytes32 increment_intermediate_hashes(mdbx::txn& txn, const std::filesystem::path& etl_dir,
                                                   const evmc::bytes32* expected_root, PrefixSet& account_changes,
                                                   PrefixSet& storage_changes) {
    etl::Collector account_collector{etl_dir};
    etl::Collector storage_collector{etl_dir};
    DbTrieLoader loader{txn, account_collector, storage_collector};
    const evmc::bytes32 root{loader.calculate_root(account_changes, storage_changes)};
    if (expected_root != nullptr && root != *expected_root) {
        log::Error() << "Wrong trie root: " << to_hex(root) << ", expected: " << to_hex(*expected_root) << "\n";
        throw WrongRoot{};
    }
    auto target{db::open_cursor(txn, db::table::kTrieOfAccounts)};
    account_collector.load(target);
    target.close();

    target = db::open_cursor(txn, db::table::kTrieOfStorage);
    storage_collector.load(target);
    target.close();

    return root;
}

// See Erigon (p *HashPromoter) Promote
static PrefixSet gather_account_changes(mdbx::txn& txn, BlockNum from) {
    const Bytes starting_key{db::block_key(from + 1)};

    PrefixSet out;

    auto account_changes{db::open_cursor(txn, db::table::kAccountChangeSet)};
    if (account_changes.lower_bound(db::to_slice(starting_key), /*throw_notfound=*/false)) {
        db::WalkFunc account_walk_function = [&out](mdbx::cursor&, mdbx::cursor::move_result& entry) {
            const ByteView address{db::from_slice(entry.value).substr(0, kAddressLength)};
            const auto hashed_address{keccak256(address)};
            out.insert(unpack_nibbles(hashed_address.bytes));
            return true;
        };
        (void)db::cursor_for_each(account_changes, account_walk_function);
    }

    return out;
}

// See Erigon (p *HashPromoter) Promote
static PrefixSet gather_storage_changes(mdbx::txn& txn, BlockNum from) {
    const Bytes starting_key{db::block_key(from + 1)};

    PrefixSet out;

    auto storage_changes{db::open_cursor(txn, db::table::kStorageChangeSet)};
    if (storage_changes.lower_bound(db::to_slice(starting_key), /*throw_notfound=*/false)) {
        db::WalkFunc storage_walk_func = [&out](mdbx::cursor&, mdbx::cursor::move_result& entry) {
            const ByteView address{db::from_slice(entry.key).substr(sizeof(BlockNum), kAddressLength)};
            const ByteView incarnation{db::from_slice(entry.key).substr(sizeof(BlockNum) + kAddressLength)};
            const ByteView location{db::from_slice(entry.value).substr(0, kHashLength)};
            const auto hashed_address{keccak256(address)};
            const auto hashed_location{keccak256(location)};

            Bytes hashed_key{ByteView{hashed_address.bytes}};
            hashed_key.append(incarnation);
            hashed_key.append(unpack_nibbles(hashed_location.bytes));
            out.insert(hashed_key);
            return true;
        };
        (void)db::cursor_for_each(storage_changes, storage_walk_func);
    }

    return out;
}

evmc::bytes32 increment_intermediate_hashes(mdbx::txn& txn, const std::filesystem::path& etl_dir, BlockNum from,
                                            const evmc::bytes32* expected_root) {
    PrefixSet account_changes{gather_account_changes(txn, from)};
    PrefixSet storage_changes{gather_storage_changes(txn, from)};
    return increment_intermediate_hashes(txn, etl_dir, expected_root, account_changes, storage_changes);
}

evmc::bytes32 regenerate_intermediate_hashes(mdbx::txn& txn, const std::filesystem::path& etl_dir,
                                             const evmc::bytes32* expected_root) {
    txn.clear_map(db::open_map(txn, db::table::kTrieOfAccounts));
    txn.clear_map(db::open_map(txn, db::table::kTrieOfStorage));
    PrefixSet empty;
    return increment_intermediate_hashes(txn, etl_dir, expected_root, /*account_changes=*/empty,
                                         /*storage_changes=*/empty);
}

std::optional<Bytes> increment_key(ByteView unpacked) {
    Bytes out{unpacked};
    for (size_t i{out.size()}; i > 0; --i) {
        uint8_t& nibble{out[i - 1]};
        SILKWORM_ASSERT(nibble < 0x10);
        if (nibble < 0xF) {
            ++nibble;
            return out;
        } else {
            nibble = 0;
            // carry over
        }
    }
    return std::nullopt;
}

}  // namespace silkworm::trie
