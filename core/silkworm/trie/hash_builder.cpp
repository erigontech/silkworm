/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "hash_builder.hpp"

#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstring>

#include <ethash/keccak.hpp>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::trie {

Bytes pack_nibbles(ByteView nibbles) {
    const size_t n{(nibbles.length() + 1) / 2};
    Bytes out(n, '\0');
    if (n == 0) {
        return out;
    }
    for (size_t i{0}; i < n - 1; ++i) {
        out[i] = (nibbles[2 * i] << 4) + nibbles[2 * i + 1];
    }
    out[n - 1] = nibbles[2 * (n - 1)] << 4;
    if (nibbles.length() % 2 == 0) {
        out[n - 1] += nibbles[2 * n - 1];
    }
    return out;
}

Bytes unpack_nibbles(ByteView packed) {
    Bytes out(2 * packed.length(), '\0');
    for (size_t i{0}; i < packed.length(); ++i) {
        out[2 * i] = packed[i] >> 4;
        out[2 * i + 1] = packed[i] & 0xF;
    }
    return out;
}

static Bytes encode_path(ByteView path, bool terminating) {
    Bytes res(path.length() / 2 + 1, '\0');
    const bool odd{path.length() % 2 != 0};

    if (!terminating && !odd) {
        res[0] = 0x00;
    } else if (!terminating && odd) {
        res[0] = 0x10;
    } else if (terminating && !odd) {
        res[0] = 0x20;
    } else if (terminating && odd) {
        res[0] = 0x30;
    }

    if (odd) {
        res[0] |= path[0];
        for (size_t i{1}; i < res.length(); ++i) {
            res[i] = (path[2 * i - 1] << 4) + path[2 * i];
        }
    } else {
        for (size_t i{1}; i < res.length(); ++i) {
            res[i] = (path[2 * i - 2] << 4) + path[2 * i - 1];
        }
    }

    return res;
}

static Bytes leaf_node_rlp(ByteView path, ByteView value) {
    Bytes encoded_path{encode_path(path, /*terminating=*/true)};
    Bytes rlp;
    rlp::Header h;
    h.list = true;
    h.payload_length = rlp::length(encoded_path) + rlp::length(value);
    rlp::encode_header(rlp, h);
    rlp::encode(rlp, encoded_path);
    rlp::encode(rlp, value);
    return rlp;
}

static Bytes extension_node_rlp(ByteView path, ByteView child_ref) {
    Bytes encoded_path{encode_path(path, /*terminating=*/false)};
    Bytes rlp;
    rlp::Header h;
    h.list = true;
    h.payload_length = rlp::length(encoded_path) + child_ref.length();
    rlp::encode_header(rlp, h);
    rlp::encode(rlp, encoded_path);
    rlp.append(child_ref);
    return rlp;
}

static Bytes wrap_hash(gsl::span<const uint8_t, kHashLength> hash) {
    Bytes wrapped(kHashLength + 1, '\0');
    wrapped[0] = rlp::kEmptyStringCode + kHashLength;
    std::memcpy(&wrapped[1], &hash[0], kHashLength);
    return wrapped;
}

static Bytes node_ref(ByteView rlp) {
    if (rlp.length() < kHashLength) {
        return Bytes{rlp};
    }
    const ethash::hash256 hash{keccak256(rlp)};
    return wrap_hash(hash.bytes);
}

void HashBuilder::add_leaf(ByteView key, ByteView value) {
    assert(key > key_);
    if (!key_.empty()) {
        gen_struct_step(key_, key);
    }
    key_ = key;
    value_ = Bytes{value};
}

void HashBuilder::add_branch_node(ByteView key, const evmc::bytes32& value, bool is_in_db_trie) {
    assert(key > key_);
    if (!key_.empty()) {
        gen_struct_step(key_, key);
    }
    key_ = key;
    value_ = value;
    is_in_db_trie_ = is_in_db_trie;
}

void HashBuilder::finalize() {
    if (!key_.empty()) {
        gen_struct_step(key_, {});
        key_.clear();
        value_ = Bytes{};
    }
}

evmc::bytes32 HashBuilder::root_hash() { return root_hash(/*auto_finalize=*/true); }

evmc::bytes32 HashBuilder::root_hash(bool auto_finalize) {
    if (auto_finalize) {
        finalize();
    }

    if (stack_.empty()) {
        return kEmptyRoot;
    }

    const Bytes& node_ref{stack_.back()};
    evmc::bytes32 res{};
    if (node_ref.length() == kHashLength + 1) {
        std::memcpy(res.bytes, &node_ref[1], kHashLength);
    } else {
        res = bit_cast<evmc_bytes32>(keccak256(node_ref));
    }
    return res;
}

// https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/guide.md#generating-the-structural-information-from-the-sequence-of-keys
void HashBuilder::gen_struct_step(ByteView current, const ByteView succeeding) {
    for (bool build_extensions{false};; build_extensions = true) {
        const bool preceding_exists{!groups_.empty()};

        // Calculate the prefix of the smallest prefix group containing current
        const size_t preceding_len{groups_.empty() ? 0 : groups_.size() - 1};
        const size_t common_prefix_len{prefix_length(succeeding, current)};
        const size_t len{std::max(preceding_len, common_prefix_len)};
        assert(len < current.length());

        // Add the digit immediately following the max common prefix
        const uint8_t extra_digit{current[len]};
        if (groups_.size() <= len) {
            groups_.resize(len + 1);
        }
        groups_[len] |= 1u << extra_digit;

        if (tree_masks_.size() < current.length()) {
            tree_masks_.resize(current.length());
            hash_masks_.resize(current.length());
        }

        size_t from{len};
        if (!succeeding.empty() || preceding_exists) {
            ++from;
        }

        const ByteView short_node_key{current.substr(from)};
        if (!build_extensions) {
            if (const Bytes * leaf_value{std::get_if<Bytes>(&value_)}) {
                stack_.push_back(node_ref(leaf_node_rlp(short_node_key, *leaf_value)));
            } else {
                stack_.push_back(wrap_hash(std::get<evmc::bytes32>(value_).bytes));
                if (node_collector) {
                    if (is_in_db_trie_) {
                        // keep track of existing records in DB
                        tree_masks_[current.length() - 1] |= 1u << current.back();
                    }
                    // register myself in parent's bitmaps
                    hash_masks_[current.length() - 1] |= 1u << current.back();
                }
                build_extensions = true;
            }
        }

        if (build_extensions && !short_node_key.empty()) {  // extension node
            if (node_collector && from > 0) {
                // See node/silkworm/trie/intermediate_hashes.hpp
                const uint16_t flag = 1u << current[from - 1];

                // DB trie can't use hash of an extension node
                hash_masks_[from - 1] &= ~flag;

                if (tree_masks_[current.length() - 1]) {
                    // Propagate tree_masks flag along the extension node
                    tree_masks_[from - 1] |= flag;
                }
            }

            stack_.back() = node_ref(extension_node_rlp(short_node_key, stack_.back()));

            hash_masks_.resize(from);
            tree_masks_.resize(from);
        }

        // Check for the optional part
        if (preceding_len <= common_prefix_len && !succeeding.empty()) {
            return;
        }

        // Close the immediately encompassing prefix group, if needed
        if (!succeeding.empty() || preceding_exists) {  // branch node
            std::vector<Bytes> child_hashes{branch_ref(groups_[len], hash_masks_[len])};

            // See node/silkworm/trie/intermediate_hashes.hpp
            if (node_collector) {
                if (len > 0) {
                    hash_masks_[len - 1] |= 1u << current[len - 1];
                }

                bool store_in_db_trie{tree_masks_[len] || hash_masks_[len]};
                if (store_in_db_trie) {
                    if (len > 0) {
                        tree_masks_[len - 1] |= 1u << current[len - 1];  // register myself in parent bitmap
                    }

                    std::vector<evmc::bytes32> hashes(child_hashes.size());
                    for (size_t i{0}; i < child_hashes.size(); ++i) {
                        assert(child_hashes[i].size() == kHashLength + 1);
                        std::memcpy(hashes[i].bytes, &child_hashes[i][1], kHashLength);
                    }
                    Node n{groups_[len], tree_masks_[len], hash_masks_[len], hashes};
                    if (len == 0) {
                        n.set_root_hash(root_hash(/*auto_finalize=*/false));
                    }

                    node_collector(current.substr(0, len), n);
                }
            }
        }

        groups_.resize(len);
        tree_masks_.resize(len);
        hash_masks_.resize(len);

        if (preceding_len == 0) {
            return;
        }

        // Update current key for the build_extensions iteration
        current = current.substr(0, preceding_len);
        while (!groups_.empty() && groups_.back() == 0) {
            groups_.pop_back();
        }
    }
}

// Takes children from the stack and replaces them with branch node ref.
std::vector<Bytes> HashBuilder::branch_ref(uint16_t state_mask, uint16_t hash_mask) {
    assert_subset(hash_mask, state_mask);
    std::vector<Bytes> child_hashes;
    child_hashes.reserve(std::bitset<16>(hash_mask).count());

    const size_t first_child_idx{stack_.size() - std::bitset<16>(state_mask).count()};

    rlp::Header h;
    h.list = true;
    h.payload_length = 1;  // for the nil value added below

    for (size_t i{first_child_idx}, digit{0}; digit < 16; ++digit) {
        if (state_mask & (1u << digit)) {
            h.payload_length += stack_[i++].length();
        } else {
            h.payload_length += 1;
        }
    }

    Bytes rlp{};
    rlp::encode_header(rlp, h);

    for (size_t i{first_child_idx}, digit{0}; digit < 16; ++digit) {
        if (state_mask & (1u << digit)) {
            if (hash_mask & (1u << digit)) {
                child_hashes.push_back(stack_[i]);
            }
            rlp.append(stack_[i++]);
        } else {
            rlp.push_back(rlp::kEmptyStringCode);
        }
    }

    // branch nodes with values are not supported
    rlp.push_back(rlp::kEmptyStringCode);

    stack_.resize(first_child_idx + 1);
    stack_.back() = node_ref(rlp);

    return child_hashes;
}

}  // namespace silkworm::trie
