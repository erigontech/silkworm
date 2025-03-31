// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "huffman_code.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>
#include <variant>
#include <vector>

#include <absl/functional/function_ref.h>

namespace silkworm::snapshots::seg {

using namespace std;

struct HuffmanTreeLeaf {
    size_t symbol_index{};
    uint64_t code{};
    uint8_t code_bits{1};
};

struct HuffmanTreeNode {
    unique_ptr<variant<HuffmanTreeNode, HuffmanTreeLeaf>> n0;
    unique_ptr<variant<HuffmanTreeNode, HuffmanTreeLeaf>> n1;
    uint64_t uses{};
    uint64_t tie_breaker{};

    bool operator<(const HuffmanTreeNode& node2) const {
        const HuffmanTreeNode& node1 = *this;
        return (node1.uses != node2.uses)
                   ? (node1.uses > node2.uses)
                   : (node1.tie_breaker > node2.tie_breaker);
    }
};

using Leaf = HuffmanTreeLeaf;
using Node = HuffmanTreeNode;

class HuffmanTree {
  public:
    explicit HuffmanTree(const vector<uint64_t>& symbol_uses)
        : root_(build(symbol_uses)) {}

    void dfs_visit_leaves(absl::FunctionRef<void(Leaf&)> visit) {
        HuffmanTree::dfs_visit_leaves(root_, visit);
    }

  private:
    static Node build(const vector<uint64_t>& symbol_uses);
    static void bump_leaves_code(Node& node, bool inc);
    static void dfs_visit_leaves(Node& node, absl::FunctionRef<void(Leaf&)> visit);

    Node root_;
};

Node HuffmanTree::build(const vector<uint64_t>& symbol_uses) {
    vector<Node> queue;
    less<> comparator;

    uint64_t tie_breaker = 0;
    size_t i = 0;

    while (queue.size() + (symbol_uses.size() - i) > 1) {
        Node node{
            .tie_breaker = tie_breaker,
        };

        // Take n0 from the heap
        if (!queue.empty() && ((i >= symbol_uses.size()) || (queue[0].uses < symbol_uses[i]))) {
            ranges::pop_heap(queue, comparator);
            node.n0 = make_unique<variant<Node, Leaf>>(std::move(queue.back()));
            queue.pop_back();

            node.uses += get<Node>(*node.n0).uses;
            bump_leaves_code(get<Node>(*node.n0), false);
        }
        // Take n0 from the list
        else {
            Leaf leaf{i, 0};
            node.n0 = make_unique<variant<Node, Leaf>>(leaf);
            node.uses += symbol_uses[i];
            ++i;
        }

        // Take n1 from the heap
        if (!queue.empty() && ((i >= symbol_uses.size()) || (queue[0].uses < symbol_uses[i]))) {
            ranges::pop_heap(queue, comparator);
            node.n1 = make_unique<variant<Node, Leaf>>(std::move(queue.back()));
            queue.pop_back();

            node.uses += get<Node>(*node.n1).uses;
            bump_leaves_code(get<Node>(*node.n1), true);
        }
        // Take n1 from the list
        else {
            Leaf leaf{i, 1};
            node.n1 = make_unique<variant<Node, Leaf>>(leaf);
            node.uses += symbol_uses[i];
            ++i;
        }

        queue.push_back(std::move(node));
        ranges::push_heap(queue, comparator);

        ++tie_breaker;
    }

    Node root;
    if (!queue.empty()) {
        root = std::move(queue[0]);
    }
    return root;
}

void HuffmanTree::bump_leaves_code(Node& node, bool inc) {
    dfs_visit_leaves(node, [inc](Leaf& leaf) {
        leaf.code <<= 1;
        leaf.code += inc ? 1 : 0;
        ++leaf.code_bits;
    });
}

void HuffmanTree::dfs_visit_leaves(Node& node, absl::FunctionRef<void(Leaf&)> visit) {
    if (node.n0) {
        auto leaf = get_if<Leaf>(node.n0.get());
        if (leaf) {
            visit(*leaf);
        } else {
            dfs_visit_leaves(get<Node>(*node.n0), visit);
        }
    }

    if (node.n1) {
        auto leaf = get_if<Leaf>(node.n1.get());
        if (leaf) {
            visit(*leaf);
        } else {
            dfs_visit_leaves(get<Node>(*node.n1), visit);
        }
    }
}

std::vector<HuffmanSymbolCode> huffman_code_table(const std::vector<uint64_t>& symbol_uses) {
    HuffmanTree tree{symbol_uses};

    std::vector<HuffmanSymbolCode> table;
    table.resize(symbol_uses.size());
    tree.dfs_visit_leaves([&table](Leaf& leaf) {
        table[leaf.symbol_index] = HuffmanSymbolCode{
            .code = leaf.code,
            .code_bits = leaf.code_bits,
        };
    });

    return table;
}

static uint64_t reverse_bytes64(uint64_t x) {
#if __cplusplus >= 202302L
    return std::byteswap(x);
#elif defined(_MSC_VER)
    return _byteswap_uint64(x);
#else
    return __builtin_bswap64(x);
#endif
}

static uint64_t reverse_bits64(uint64_t x) {
    // every even bit (01010101...)
    constexpr uint64_t kMask1 = 0x5555555555555555;
    // every even bit pair (00110011...)
    constexpr uint64_t kMask2 = 0x3333333333333333;
    // every even nibble (00001111...)
    constexpr uint64_t kMask4 = 0x0F0F0F0F0F0F0F0F;

    // reverse bits in each byte
    x = ((x >> 1) & kMask1) | ((x & kMask1) << 1);
    x = ((x >> 2) & kMask2) | ((x & kMask2) << 2);
    x = ((x >> 4) & kMask4) | ((x & kMask4) << 4);

    return reverse_bytes64(x);
}

std::vector<size_t> huffman_code_table_order_by_codes(
    const std::vector<HuffmanSymbolCode>& codes) {
    std::vector<size_t> order(codes.size());
    std::iota(order.begin(), order.end(), 0);

    std::ranges::sort(order, [&](size_t i, size_t j) {
        return reverse_bits64(codes[i].code) < reverse_bits64(codes[j].code);
    });
    return order;
}

std::vector<size_t> huffman_code_table_order_by_uses_and_codes(
    const std::vector<uint64_t>& symbol_uses,
    const std::vector<uint64_t>& codes) {
    std::vector<size_t> order(symbol_uses.size());
    std::iota(order.begin(), order.end(), 0);

    std::ranges::sort(order, [&](size_t i, size_t j) {
        return (symbol_uses[i] != symbol_uses[j])
                   ? (symbol_uses[i] < symbol_uses[j])
                   : (reverse_bits64(codes[i]) < reverse_bits64(codes[j]));
    });
    return order;
}

}  // namespace silkworm::snapshots::seg
