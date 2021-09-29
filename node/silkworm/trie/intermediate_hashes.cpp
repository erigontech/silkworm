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

#include "intermediate_hashes.hpp"

#include <bitset>

#include <silkworm/common/log.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::trie {

AccountTrieCursor::AccountTrieCursor(mdbx::txn& txn, const PrefixSet& changed)
    : changed_{changed}, cursor_{db::open_cursor(txn, db::table::kTrieOfAccounts)} {}

void AccountTrieCursor::seek_node(ByteView to) {
    const auto entry{cursor_.lower_bound(db::to_slice(to), /*throw_notfound=*/false)};
    if (!entry) {
        // end-of-tree
        return;
    }
    const auto node{unmarshal_node(db::from_slice(entry.value))};
    assert(node != std::nullopt);
    assert(node->state_mask() != 0);
    uint8_t nibble{0};
    while ((node->state_mask() & (1u << nibble)) == 0) {
        ++nibble;
    }
    stack_.push(SubNode{Bytes{db::from_slice(entry.key)}, *node, nibble});
}

void AccountTrieCursor::next(bool skip_children) {
    if (at_root_) {
        seek_node({});
        at_root_ = false;
        return;
    }

    if (stack_.empty()) {
        // end-of-tree
        return;
    }

    if (!skip_children && children_are_in_trie()) {
        seek_node(*key());
        return;
    }

    move_to_next_sibling();
}

void AccountTrieCursor::move_to_next_sibling() {
    if (stack_.empty()) {
        return;
    }

    SubNode& sn{stack_.top()};

    assert(sn.nibble < 16);
    do {
        ++sn.nibble;
        if (sn.nibble == 16) {
            // this node is fully traversed
            stack_.pop();
            move_to_next_sibling();  // on parent
            return;
        }
    } while (!sn.state_flag());
}

Bytes AccountTrieCursor::SubNode::full_key() const {
    Bytes out{key};
    out.push_back(nibble);
    return out;
}

bool AccountTrieCursor::SubNode::state_flag() const { return node.state_mask() & (1u << nibble); }

bool AccountTrieCursor::SubNode::tree_flag() const { return node.tree_mask() & (1u << nibble); }

bool AccountTrieCursor::SubNode::hash_flag() const { return node.hash_mask() & (1u << nibble); }

const evmc::bytes32* AccountTrieCursor::SubNode::hash() const {
    if (!hash_flag()) {
        return nullptr;
    }
    const unsigned first_nibbles_mask{(1u << nibble) - 1};
    const size_t hash_idx{std::bitset<16>(node.hash_mask() & first_nibbles_mask).count()};
    return &node.hashes()[hash_idx];
}

std::optional<Bytes> AccountTrieCursor::key() const {
    if (at_root_) {
        return Bytes{};
    }
    if (stack_.empty()) {
        return std::nullopt;
    }
    return stack_.top().full_key();
}

const evmc::bytes32* AccountTrieCursor::hash() const {
    if (stack_.empty()) {
        return nullptr;
    }
    return stack_.top().hash();
}

bool AccountTrieCursor::children_are_in_trie() const {
    if (stack_.empty()) {
        return false;
    }
    return stack_.top().tree_flag();
}

bool AccountTrieCursor::can_skip_state() const {
    if (at_root_) {
        return false;
    }
    const std::optional<Bytes> k{key()};
    if (k == std::nullopt || changed_.contains(pack_nibbles(*k))) {
        return false;
    }
    return stack_.top().hash_flag();
}

StorageTrieCursor::StorageTrieCursor(mdbx::txn&) {}

Bytes StorageTrieCursor::seek_to_account(ByteView) {
    // TODO[Issue 179] implement
    return {};
}

Bytes StorageTrieCursor::first_uncovered_prefix() {
    // TODO[Issue 179] implement
    return Bytes(1, '\0');
}

std::optional<Bytes> StorageTrieCursor::key() const {
    // TODO[Issue 179] implement
    return std::nullopt;
}

void StorageTrieCursor::next() {
    // TODO[Issue 179] implement
}

bool StorageTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

DbTrieLoader::DbTrieLoader(mdbx::txn& txn, etl::Collector& account_collector, etl::Collector& storage_collector)
    : txn_{txn}, storage_collector_{storage_collector} {
    hb_.node_collector = [&account_collector](ByteView unpacked_key, const std::optional<Node>& node) {
        if (unpacked_key.empty()) {
            return;
        }

        etl::Entry e;
        e.key = unpacked_key;
        if (node != std::nullopt) {
            e.value = marshal_node(*node);
        }

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
evmc::bytes32 DbTrieLoader::calculate_root(const PrefixSet& changed) {
    auto acc_state{db::open_cursor(txn_, db::table::kHashedAccounts)};
    auto storage_state{db::open_cursor(txn_, db::table::kHashedStorage)};

    for (AccountTrieCursor acc_trie{txn_, changed}; acc_trie.key() != std::nullopt;) {
        if (acc_trie.can_skip_state()) {
            assert(acc_trie.hash() != nullptr);
            hb_.add_branch_node(*acc_trie.key(), *acc_trie.hash(), acc_trie.children_are_in_trie());
            acc_trie.next(/*skip_children=*/true);
            continue;
        }

        const Bytes first_uncovered_prefix{pack_nibbles(*acc_trie.key())};
        acc_trie.next(/*skip_children=*/false);

        for (auto acc{acc_state.lower_bound(db::to_slice(first_uncovered_prefix), /*throw_notfound=*/false)}; acc.done;
             acc = acc_state.to_next(/*throw_notfound=*/false)) {
            const Bytes unpacked_key{unpack_nibbles(db::from_slice(acc.key))};
            if (acc_trie.key().has_value() && acc_trie.key().value() < unpacked_key) {
                break;
            }
            const auto [account, err]{decode_account_from_storage(db::from_slice(acc.value))};
            rlp::err_handler(err);

            evmc::bytes32 storage_root{kEmptyRoot};

            if (account.incarnation) {
                const Bytes key_with_inc{db::storage_prefix(db::from_slice(acc.key), account.incarnation)};
                HashBuilder storage_hb;
                storage_hb.node_collector = [&](ByteView unpacked_storage_key, const std::optional<Node>& node) {
                    etl::Entry e;
                    e.key = key_with_inc;
                    e.key.append(unpacked_storage_key);
                    if (node != std::nullopt) {
                        e.value = marshal_node(*node);
                    }
                    storage_collector_.collect(std::move(e));
                };

                StorageTrieCursor storage_trie{txn_};
                for (storage_trie.seek_to_account(key_with_inc);; storage_trie.next()) {
                    if (storage_trie.can_skip_state()) {
                        goto use_storage_trie;
                    }

                    for (auto storage{storage_state.lower_bound_multivalue(
                             db::to_slice(key_with_inc), db::to_slice(storage_trie.first_uncovered_prefix()),
                             /*throw_notfound=*/false)};
                         storage.done; storage = storage_state.to_current_next_multi(/*throw_notfound=*/false)) {
                        const Bytes unpacked_loc{unpack_nibbles(db::from_slice(storage.value).substr(0, kHashLength))};
                        const ByteView value{db::from_slice(storage.value).substr(kHashLength)};
                        if (storage_trie.key().has_value() && storage_trie.key().value() < unpacked_loc) {
                            break;
                        }

                        rlp_.clear();
                        rlp::encode(rlp_, value);
                        storage_hb.add_leaf(unpacked_loc, rlp_);
                    }

                use_storage_trie:
                    if (storage_trie.key() == std::nullopt) {
                        break;
                    }

                    // TODO[Issue 179] use storage trie
                }

                storage_root = storage_hb.root_hash();
            }

            hb_.add_leaf(unpacked_key, account.rlp(storage_root));
        }
    }

    return hb_.root_hash();
}

static evmc::bytes32 increment_intermediate_hashes(mdbx::txn& txn, const std::filesystem::path& etl_dir,
                                                   const evmc::bytes32* expected_root, const PrefixSet& changed) {
    etl::Collector account_collector{etl_dir};
    etl::Collector storage_collector{etl_dir};
    DbTrieLoader loader{txn, account_collector, storage_collector};
    const evmc::bytes32 root{loader.calculate_root(changed)};
    if (expected_root != nullptr && root != *expected_root) {
        SILKWORM_LOG(LogLevel::Error) << "Wrong trie root: " << to_hex(root) << ", expected: " << to_hex(*expected_root)
                                      << "\n";
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
static void changed_accounts(mdbx::txn& txn, BlockNum from, PrefixSet& out) {
    // TODO[Issue 179] delete TrieStorage for deleted accounts
    const Bytes starting_key{db::block_key(from + 1)};

    auto change_cursor{db::open_cursor(txn, db::table::kAccountChangeSet)};
    change_cursor.lower_bound(db::to_slice(starting_key), /*throw_notfound=*/false);
    db::for_each(change_cursor, [&out](mdbx::cursor::move_result& entry) {
        const ByteView address{db::from_slice(entry.value).substr(0, kAddressLength)};
        const auto hashed_address{keccak256(address)};
        out.insert(ByteView{hashed_address.bytes, kHashLength});
        return true;
    });
}

evmc::bytes32 increment_intermediate_hashes(mdbx::txn& txn, const std::filesystem::path& etl_dir, BlockNum from,
                                            const evmc::bytes32* expected_root) {
    PrefixSet changed;
    changed_accounts(txn, from, changed);
    // TODO[Issue 179] changed storage
    return increment_intermediate_hashes(txn, etl_dir, expected_root, changed);
}

evmc::bytes32 regenerate_intermediate_hashes(mdbx::txn& txn, const std::filesystem::path& etl_dir,
                                             const evmc::bytes32* expected_root) {
    txn.clear_map(db::open_map(txn, db::table::kTrieOfAccounts));
    txn.clear_map(db::open_map(txn, db::table::kTrieOfStorage));
    return increment_intermediate_hashes(txn, etl_dir, expected_root, /*changed=*/{});
}

}  // namespace silkworm::trie
