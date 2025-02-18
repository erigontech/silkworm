/*
   Copyright 2024 The Silkworm Authors

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

#include "patricia_tree.hpp"

#include <sais.h>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "lcp_kasai.hpp"

namespace silkworm::snapshots::seg {

struct PatriciaTreeNode {
    void insert(ByteView key, void* value);
    void* get(ByteView key);

    //! Value associated with the key.
    void* value{};
    std::unique_ptr<PatriciaTreeNode> n0;
    std::unique_ptr<PatriciaTreeNode> n1;
    uint32_t p0{};
    uint32_t p1{};
};
using Node = PatriciaTreeNode;

// state represent a position anywhere inside patricia tree
// position can be identified by combination of node, and the partitioning
// of that node's p0 or p1 into head and tail.
// As with p0 and p1, head and tail are encoded as follows:
// lowest 5 bits encode the length in bits, and the remaining 27 bits
// encode the actual head or tail.
// For example, if the position is at the beginning of a node,
// head would be zero, and tail would be equal to either p0 or p1,
// depending on whether the position corresponds to going left (0) or right (1).
struct PatriciaTreePathWalker {
    explicit PatriciaTreePathWalker(Node* n1) : n(n1) {}

    void reset(Node* n1) {
        this->n = n1;
        this->head = 0;
        this->tail = 0;
    }

    /**
     * Consumes the next byte of the key
     * and moves the state to corresponding node of the patricia tree.
     * @return divergence prefix (0 if there is no divergence)
     */
    uint32_t transition(unsigned char b, bool readonly);

    void diverge(uint32_t divergence);

    void insert(void* value);

    Node* n{};
    uint32_t head{};
    uint32_t tail{};
};

static uint32_t shift_left(uint32_t x, uint32_t bits) {
    if (bits >= 32) return 0;
    return x << bits;
}

static uint32_t shift_right(uint32_t x, uint32_t bits) {
    if (bits >= 32) return 0;
    return x >> bits;
}

uint32_t PatriciaTreePathWalker::transition(unsigned char b, bool readonly) {
    PatriciaTreePathWalker* s = this;
    // bits in b to process
    uint32_t bits_left = 8;
    uint32_t b32 = static_cast<uint32_t>(b) << 24;

    while (bits_left > 0) {
        if (s->head == 0) {
            // tail has not been determined yet, do it now
            if ((b32 & 0x80000000) == 0) {
                s->tail = s->n->p0;
            } else {
                s->tail = s->n->p1;
            }
        }

        if (s->tail == 0) {
            // state positioned at the end of the current node
            return b32 | bits_left;
        }

        uint32_t tail_len = s->tail & 0x1f;
        // the first bit where b32 and tail are different
        auto first_diff = static_cast<uint32_t>(std::countl_zero(s->tail ^ b32));

        if (first_diff < bits_left) {
            // divergence (where the key being searched and the existing structure of patricia tree becomes incompatible) is within currently supplied byte of the search key, b
            if (first_diff >= tail_len) {
                // divergence is within currently supplied byte of the search key, b, but outside the current node
                bits_left -= tail_len;
                b32 = shift_left(b32, tail_len);

                if (((s->head == 0) && ((s->tail & 0x80000000) == 0)) || ((s->head != 0) && ((s->head & 0x80000000) == 0))) {
                    if (s->n->n0 == nullptr) {
                        throw std::runtime_error("PatriciaTreePathWalker::transition: Node n0 is null");
                    }
                    s->n = s->n->n0.get();
                } else {
                    if (s->n->n1 == nullptr) {
                        throw std::runtime_error("PatriciaTreePathWalker::transition: Node n1 is null");
                    }
                    s->n = s->n->n1.get();
                }
                s->head = 0;
                s->tail = 0;
            } else {
                // divergence is within currently supplied byte of the search key, b, and within the current node
                bits_left -= first_diff;
                b32 = shift_left(b32, first_diff);

                // there is divergence, move head and tail
                uint32_t mask = ~(shift_left(1, 32 - first_diff) - 1);
                s->head |= shift_right(s->tail & mask, s->head & 0x1f);
                s->head += first_diff;
                s->tail = shift_left(s->tail & 0xffffffe0, first_diff) | (s->tail & 0x1f);
                s->tail -= first_diff;
                return b32 | bits_left;
            }
        } else if (tail_len < bits_left) {
            // divergence is outside the currently supplied byte of the search key, b
            bits_left -= tail_len;
            b32 = shift_left(b32, tail_len);

            // switch to the next node
            if (((s->head == 0) && ((s->tail & 0x80000000) == 0)) || ((s->head != 0) && ((s->head & 0x80000000) == 0))) {
                if (s->n->n0 == nullptr) {
                    if (readonly) {
                        return b32 | bits_left;
                    }
                    s->n->n0 = std::make_unique<Node>();
                    if ((b32 & 0x80000000) == 0) {
                        s->n->n0->p0 = b32 | bits_left;
                    } else {
                        s->n->n0->p1 = b32 | bits_left;
                    }
                }
                s->n = s->n->n0.get();
            } else {
                if (s->n->n1 == nullptr) {
                    if (readonly) {
                        return b32 | bits_left;
                    }
                    s->n->n1 = std::make_unique<Node>();
                    if ((b32 & 0x80000000) == 0) {
                        s->n->n1->p0 = b32 | bits_left;
                    } else {
                        s->n->n1->p1 = b32 | bits_left;
                    }
                }
                s->n = s->n->n1.get();
            }
            s->head = 0;
            s->tail = 0;
        } else {
            // key byte is consumed, but stay on the same node
            uint32_t mask = ~(shift_left(1, 32 - bits_left) - 1);
            s->head |= shift_right(s->tail & mask, s->head & 0x1f);
            s->head += bits_left;
            s->tail = shift_left(s->tail & 0xffffffe0, bits_left) | (s->tail & 0x1f);
            s->tail -= bits_left;
            bits_left = 0;

            if (s->tail == 0) {
                if ((s->head & 0x80000000) == 0) {
                    if (s->n->n0) {
                        s->n = s->n->n0.get();
                        s->head = 0;
                    }
                } else {
                    if (s->n->n1) {
                        s->n = s->n->n1.get();
                        s->head = 0;
                    }
                }
            }
        }
    }

    return 0;
}

void PatriciaTreePathWalker::diverge(uint32_t divergence) {
    if (tail == 0) {
        // try to add to the existing head
        uint32_t d_len = divergence & 0x1f;
        uint32_t head_len = head & 0x1f;
        uint32_t d32 = divergence & 0xffffffe0;

        if (head_len + d_len > 27) {
            uint32_t mask = ~(shift_left(1, head_len + 5) - 1);
            head |= shift_right(d32 & mask, head_len);
            head += 27 - head_len;

            if (((head == 0) && ((tail & 0x80000000) == 0)) || ((head != 0) && ((head & 0x80000000) == 0))) {
                n->p0 = head;
                n->n0 = std::make_unique<Node>();
                n = n->n0.get();
            } else {
                n->p1 = head;
                n->n1 = std::make_unique<Node>();
                n = n->n1.get();
            }

            head = 0;
            tail = 0;
            d32 <<= 27 - head_len;
            d_len -= (27 - head_len);
            head_len = 0;
        }

        uint32_t mask = ~(shift_left(1, 32 - d_len) - 1);
        head |= shift_right(d32 & mask, head_len);
        head += d_len;

        if (((head == 0) && ((tail & 0x80000000) == 0)) || ((head != 0) && ((head & 0x80000000) == 0))) {
            n->p0 = head;
        } else {
            n->p1 = head;
        }

        return;
    }

    // create a new node
    auto dn_ptr = std::make_unique<Node>();
    Node& dn = *dn_ptr;

    if ((divergence & 0x80000000) == 0) {
        dn.p0 = divergence;
        dn.p1 = tail;

        if (((head == 0) && ((tail & 0x80000000) == 0)) || ((head != 0) && ((head & 0x80000000) == 0))) {
            dn.n1 = std::move(n->n0);
        } else {
            dn.n1 = std::move(n->n1);
        }
    } else {
        dn.p1 = divergence;
        dn.p0 = tail;

        if (((head == 0) && ((tail & 0x80000000) == 0)) || ((head != 0) && ((head & 0x80000000) == 0))) {
            dn.n0 = std::move(n->n0);
        } else {
            dn.n0 = std::move(n->n1);
        }
    }

    if (((head == 0) && ((tail & 0x80000000) == 0)) || ((head != 0) && ((head & 0x80000000) == 0))) {
        n->n0 = std::move(dn_ptr);
        n->p0 = head;
        n = n->n0.get();
    } else {
        n->n1 = std::move(dn_ptr);
        n->p1 = head;
        n = n->n1.get();
    }

    head = divergence;
    tail = 0;
}

void Node::insert(ByteView key, void* value1) {
    PatriciaTreePathWalker walker(this);
    for (unsigned char c : key) {
        uint32_t divergence = walker.transition(c, /* readonly */ false);
        if (divergence != 0) {
            walker.diverge(divergence);
        }
    }
    walker.insert(value1);
}

void PatriciaTreePathWalker::insert(void* value) {
    if (tail != 0) {
        diverge(0);
    }
    if (head != 0) {
        if ((head & 0x80000000) == 0) {
            n->n0 = std::make_unique<Node>();
            n = n->n0.get();
        } else {
            n->n1 = std::make_unique<Node>();
            n = n->n1.get();
        }
        head = 0;
    }
    n->value = value;
}

void* Node::get(ByteView key) {
    PatriciaTreePathWalker walker(this);
    for (unsigned char c : key) {
        uint32_t divergence = walker.transition(c, /* readonly */ true);
        if (divergence != 0) {
            return nullptr;
        }
    }
    if (walker.tail != 0) {
        return nullptr;
    }
    return walker.n->value;
}

class PatriciaTreeImpl {
  public:
    void insert(ByteView key, void* value) {
        root.insert(key, value);
    }

    void* get(ByteView key) {
        return root.get(key);
    }

    Node root;
};

class PatriciaTreeMatchFinderImpl {
  public:
    explicit PatriciaTreeMatchFinderImpl(const PatriciaTreeImpl& tree1)
        : tree(tree1),
          node_stack({&(tree.root)}),
          top(&(tree.root)) {}

    /**
     * Consumes next byte of the key,
     * moves the state to corresponding node of the patricia tree.
     * @return divergence prefix (0 if there is no divergence)
     */
    uint32_t unfold(unsigned char b);

    //! Moves the match finder back up the stack by specified number of bits.
    void fold(size_t bits);

    const std::vector<PatriciaTreeMatchFinder::Match>& find_longest_matches(ByteView data);

    std::pair<Bytes, size_t> current();

    const PatriciaTreeImpl& tree;
    std::vector<const Node*> node_stack;
    // top of the node stack
    const Node* top{};
    std::vector<PatriciaTreeMatchFinder::Match> match_stack;
    std::vector<PatriciaTreeMatchFinder::Match> matches;
    std::vector<int> sa;
    std::vector<int> lcp;
    std::vector<int> inv;
    uint32_t head_len{};
    uint32_t tail_len{};
    // 0, 1, or 2 (if side is not determined yet)
    enum Side : uint8_t {
        kSide0,
        kSide1,
        kSideNotDetermined,
    } side{kSideNotDetermined};
};

uint32_t PatriciaTreeMatchFinderImpl::unfold(unsigned char b) {
    // bits in b to process
    uint32_t bits_left = 8;
    uint32_t b32 = static_cast<uint32_t>(b) << 24;

    while (bits_left > 0) {
        if (side == kSideNotDetermined) {
            // tail has not been determined yet, do it now
            if ((b32 & 0x80000000) == 0) {
                side = kSide0;
                head_len = 0;
                tail_len = top->p0 & 0x1f;
            } else {
                side = kSide1;
                head_len = 0;
                tail_len = top->p1 & 0x1f;
            }

            if (tail_len == 0) {
                // state positioned at the end of the current node
                side = kSideNotDetermined;
                return b32 | bits_left;
            }
        }

        if (tail_len == 0) {
            // need to switch to the next node
            if (side == kSide0) {
                if (top->n0 == nullptr) {
                    return b32 | bits_left;
                }
                node_stack.push_back(top->n0.get());
                top = top->n0.get();
            } else if (side == kSide1) {
                if (top->n1 == nullptr) {
                    return b32 | bits_left;
                }
                node_stack.push_back(top->n1.get());
                top = top->n1.get();
            } else {
#ifndef NDEBUG
                SILKWORM_ASSERT(false);
#else
                throw std::runtime_error("PatriciaTreeMatchFinder::unfold: unexpected condition side > 1");
#endif
            }

            head_len = 0;
            side = kSideNotDetermined;
        }

        uint32_t tail = 0;
        if (side == kSide0) {
            tail = shift_left(top->p0 & 0xffffffe0, head_len);
        } else if (side == kSide1) {
            tail = shift_left(top->p1 & 0xffffffe0, head_len);
        } else {
            return b32 | bits_left;
        }

        // the first bit where b32 and tail are different
        auto first_diff = static_cast<uint32_t>(std::countl_zero(tail ^ b32));

        if (first_diff < bits_left) {
            // divergence (where the key being searched and the existing structure of patricia tree becomes incompatible) is within currently supplied byte of the search key, b
            if (first_diff >= tail_len) {
                // divergence is within currently supplied byte of the search key, b, but outside the current node
                bits_left -= tail_len;
                b32 = shift_left(b32, tail_len);
                head_len += tail_len;
                tail_len = 0;
            } else {
                // divergence is within currently supplied byte of the search key, b, and within the current node
                bits_left -= first_diff;
                b32 = shift_left(b32, first_diff);
                // there is divergence, move head and tail
                tail_len -= first_diff;
                head_len += first_diff;
                return b32 | bits_left;
            }
        } else if (tail_len < bits_left) {
            // divergence is outside the currently supplied byte of the search key, b
            bits_left -= tail_len;
            b32 = shift_left(b32, tail_len);
            head_len += tail_len;
            tail_len = 0;
        } else {
            // key byte is consumed, but stay on the same node
            tail_len -= bits_left;
            head_len += bits_left;
            bits_left = 0;
            b32 = 0;
        }

        if (tail_len == 0) {
            // need to switch to the next node
            if (side == kSide0) {
                if (top->n0 == nullptr) {
                    return b32 | bits_left;
                }
                node_stack.push_back(top->n0.get());
                top = top->n0.get();
            } else if (side == kSide1) {
                if (top->n1 == nullptr) {
                    return b32 | bits_left;
                }
                node_stack.push_back(top->n1.get());
                top = top->n1.get();
            } else {
#ifndef NDEBUG
                SILKWORM_ASSERT(false);
#else
                throw std::runtime_error("PatriciaTreeMatchFinder::unfold: unexpected condition side > 1");
#endif
            }

            head_len = 0;
            side = kSideNotDetermined;
        }
    }

    return 0;
}

// moves the match finder back up the stack by specified number of bits
void PatriciaTreeMatchFinderImpl::fold(size_t bits) {
    auto bits_left = static_cast<uint32_t>(bits);
    while (bits_left > 0) {
        if (head_len == bits_left) {
            head_len = 0;
            tail_len = 0;
            side = kSideNotDetermined;
            bits_left = 0;
        } else if (head_len >= bits_left) {
            // folding only affects top node, take bits from end of the head and prepend it to the tail
            head_len -= bits_left;
            tail_len += bits_left;
            bits_left = 0;
        } else {
            // folding affects not only top node, remove top node
            bits_left -= head_len;
            node_stack.pop_back();
            const Node* prev_top = top;
            top = node_stack.back();
            if (top->n0.get() == prev_top) {
                side = kSide0;
                head_len = top->p0 & 0x1f;
            } else if (top->n1.get() == prev_top) {
                side = kSide1;
                head_len = top->p1 & 0x1f;
            } else {
#ifndef NDEBUG
                SILKWORM_ASSERT(false);
#else
                throw std::runtime_error("PatriciaTreeMatchFinder::fold: unexpected condition top prev_top is not a top child");
#endif
            }
            tail_len = 0;
        }
    }
}

const std::vector<PatriciaTreeMatchFinder::Match>& PatriciaTreeMatchFinderImpl::find_longest_matches(ByteView data) {
    matches.clear();
    if (data.size() < 2) {
        return matches;
    }

    node_stack.clear();
    node_stack.push_back(&tree.root);
    match_stack.clear();
    top = &tree.root;
    side = kSideNotDetermined;
    tail_len = 0;
    head_len = 0;

    size_t n = data.size();
    sa.resize(n);
    if (sais(data.data(), sa.data(), static_cast<int>(n)) != 0) {
        throw std::runtime_error("PatriciaTreeMatchFinder::find_longest_matches: sais algorithm failed");
    }

    inv.resize(n);
    for (size_t i = 0; i < n; ++i) {
        inv[static_cast<size_t>(sa[i])] = static_cast<int>(i);
    }

    lcp.resize(n);
    lcp_kasai(data.data(), sa.data(), inv.data(), lcp.data(), static_cast<int>(n));

    // depth in bits
    size_t depth = 0;
    PatriciaTreeMatchFinder::Match* last_match = nullptr;
    for (size_t i = 0; i < n; ++i) {
        // lcp[i] is the Longest Common Prefix of suffixes starting from sa[i] and sa[i+1]
        if (i > 0) {
            auto lcp1 = static_cast<size_t>(this->lcp[i - 1]);
            // lcp[i-1] is the Longest Common Prefix of suffixes starting from sa[i-1] and sa[i]
            if (depth > 8 * lcp1) {
                this->fold(depth - 8 * lcp1);
                depth = 8 * lcp1;
                while (last_match && (last_match->end - last_match->start > lcp1)) {
                    this->match_stack.pop_back();
                    if (this->match_stack.empty()) {
                        last_match = nullptr;
                    } else {
                        last_match = &this->match_stack.back();
                    }
                }
            } else {
                size_t r = depth % 8;
                if (r > 0) {
                    this->fold(r);
                    depth -= r;
                }
            }
        }
        auto sa1 = static_cast<size_t>(this->sa[i]);
        size_t start = sa1 + depth / 8;
        for (size_t end = start + 1; end <= n; ++end) {
            uint32_t d = this->unfold(data[end - 1]);
            depth += 8 - (d & 0x1f);
            // divergence found
            if (d != 0) {
                break;
            }
            if ((this->tail_len != 0) || (this->top->value == nullptr)) {
                continue;
            }

            // this possibly overwrites the previous match for the same start position
            PatriciaTreeMatchFinder::Match match{
                .value = this->top->value,
                .start = sa1,
                .end = end,
            };
            this->match_stack.push_back(match);
            last_match = &this->match_stack.back();
        }

        if (last_match) {
            PatriciaTreeMatchFinder::Match match{
                .value = last_match->value,
                .start = sa1,
                .end = sa1 + last_match->end - last_match->start,
            };
            this->matches.push_back(match);
        }
    }

    if (this->matches.size() < 2) {
        return this->matches;
    }

    std::ranges::sort(
        this->matches,
        [](const PatriciaTreeMatchFinder::Match& i, const PatriciaTreeMatchFinder::Match& j) { return i.start < j.start; });

    size_t last_end = this->matches[0].end;
    size_t j = 1;
    for (size_t i = 1; i < this->matches.size(); ++i) {
        const PatriciaTreeMatchFinder::Match& m = this->matches[i];
        if (m.end > last_end) {
            if (i != j) {
                this->matches[j] = m;
            }
            last_end = m.end;
            ++j;
        }
    }

    this->matches.resize(j);
    return this->matches;
}

std::pair<Bytes, size_t> PatriciaTreeMatchFinderImpl::current() {
    Bytes b;
    size_t depth = 0;
    size_t last = node_stack.size() - 1;

    for (size_t i = 0; i < node_stack.size(); ++i) {
        const Node* n = node_stack[i];
        uint32_t p = 0;

        if (i < last) {
            const Node* next = node_stack[i + 1];
            if (n->n0.get() == next) {
                p = n->p0;
            } else if (n->n1.get() == next) {
                p = n->p1;
            } else {
#ifndef NDEBUG
                SILKWORM_ASSERT(false);
#else
                throw std::runtime_error("PatriciaTreeMatchFinder::current: unexpected condition next is not a child of n");
#endif
            }
        } else {
            if (side == kSide0) {
                p = n->p0;
            } else if (side == kSide1) {
                p = n->p1;
            }
            p = (p & 0xffffffe0) | head_len;
        }

        // add bit by bit
        while ((p & 0x1f) > 0) {
            if (depth >= 8 * b.size()) {
                b.push_back(0);
            }
            if (p & 0x80000000) {
                b[depth / 8] |= uint8_t{1} << (7 - (depth % 8));
            }
            ++depth;
            p = ((p & 0xffffffe0) << 1) | ((p & 0x1f) - 1);
        }
    }

    return std::make_pair(b, depth);
}

PatriciaTree::PatriciaTree() : p_impl_(std::make_unique<PatriciaTreeImpl>()) {}
PatriciaTree::~PatriciaTree() { static_assert(true); }

void PatriciaTree::insert(ByteView key, void* value) {
    p_impl_->insert(key, value);
}
void* PatriciaTree::get(ByteView key) {
    return p_impl_->get(key);
}

PatriciaTreeMatchFinder::PatriciaTreeMatchFinder(const PatriciaTree& tree) : p_impl_(std::make_unique<PatriciaTreeMatchFinderImpl>(*tree.p_impl_)) {}
PatriciaTreeMatchFinder::~PatriciaTreeMatchFinder() { static_assert(true); }

const std::vector<PatriciaTreeMatchFinder::Match>& PatriciaTreeMatchFinder::find_longest_matches(ByteView data) {
    return p_impl_->find_longest_matches(data);
}

}  // namespace silkworm::snapshots::seg
