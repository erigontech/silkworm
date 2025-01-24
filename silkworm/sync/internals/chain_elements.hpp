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

#include <map>
#include <queue>
#include <set>
#include <span>
#include <stack>
#include <utility>
#include <vector>

#include <silkworm/db/access_layer.hpp>

#include "priority_queue.hpp"
#include "types.hpp"

namespace silkworm {

// Auxiliary types needed to implement WorkingChain

// A link corresponds to a block header, links are connected to each other by reverse of parent_hash relation
struct Link {
    std::shared_ptr<BlockHeader> header;      // Header to which this link point to
    BlockNum block_num = 0;                   // Block block_num of the header, repeated here for convenience (remove?)
    Hash hash;                                // Hash of the header
    std::vector<std::shared_ptr<Link>> next;  // Reverse of parent_hash,allows iter.over links in asc. block number order
    bool persisted = false;                   // Whether this link comes from the database record
    bool preverified = false;                 // Ancestor of pre-verified header

    Link(BlockHeader h, bool persist)
        : block_num{h.number},
          hash{h.hash()},  // save computation
          persisted{persist} {
        header = std::make_shared<BlockHeader>(std::move(h));
    }

    void remove_child(const Link& child) {
        std::erase_if(next, [child](auto& link) { return (link->hash == child.hash); });
    }

    auto find_child(const Hash& h) {
        return std::find_if(next.begin(), next.end(), [h](auto& link) { return (link->hash == h); });
    }

    bool has_child(const Hash& h) { return find_child(h) != next.end(); }
};

// An anchor is the bottom of a chain bundle that consists of one anchor and some chain links.
struct Anchor {
    Hash parent_hash;                          // Hash of the header this anchor can be connected to (to disappear)
    BlockNum block_num;                        // block number of the anchor
    time_point_t timestamp;                    // request/arrival time
    time_point_t prev_timestamp;               // Used to restore timestamp when a request fails for network reasons
    int timeouts{0};                           // Number of timeout that this anchor has experienced; after certain threshold, it gets invalidated
    std::vector<std::shared_ptr<Link>> links;  // Links attached immediately to this anchor
    BlockNum last_link_block_num{0};           // the block_num of the last link of the chain bundle anchored to this
    PeerId peer_id;

    Anchor(const BlockHeader& header, PeerId p)
        : parent_hash{header.parent_hash},
          block_num{header.number},
          last_link_block_num{block_num},
          // timestamp{0},  // ready to get extended
          peer_id{std::move(p)} {
    }

    BlockNum chain_length() const { return last_link_block_num - block_num + 1; }

    void remove_child(const Link& child) {
        std::erase_if(links, [child](auto& link) { return (link->hash == child.hash); });
    }

    auto find_child(const Hash& h) {
        return std::find_if(links.begin(), links.end(), [h](auto& link) { return (link->hash == h); });
    }

    bool has_child(const Hash& h) { return find_child(h) != links.end(); }

    void update_timestamp(time_point_t time_point) {
        prev_timestamp = timestamp;
        timestamp = time_point;
        ++timeouts;
    }

    void restore_timestamp() {
        --timeouts;
        timestamp = prev_timestamp;
    }
};

// Binary relations to use in priority queues
struct LinkOlderThan : public std::function<bool(std::shared_ptr<Link>, std::shared_ptr<Link>)> {
    bool operator()(const std::shared_ptr<Link>& x, const std::shared_ptr<Link>& y) const {
        return x->block_num != y->block_num ? x->block_num < y->block_num :  // cause ordering
                   x < y;                                                    // preserve identity
    }
};

struct LinkYoungerThan : public std::function<bool(std::shared_ptr<Link>, std::shared_ptr<Link>)> {
    bool operator()(const std::shared_ptr<Link>& x, const std::shared_ptr<Link>& y) const {
        return x->block_num != y->block_num ? x->block_num > y->block_num :  // cause ordering
                   x > y;                                                    // preserve identity
    }
};

struct AnchorYoungerThan : public std::function<bool(std::shared_ptr<Link>, std::shared_ptr<Link>)> {
    bool operator()(const std::shared_ptr<Anchor>& x, const std::shared_ptr<Anchor>& y) const {
        if (x->timestamp != y->timestamp) {
            return x->timestamp > y->timestamp;  // prefer smaller timestamp
        }
        if (x->block_num != y->block_num) {
            return x->block_num > y->block_num;  // when timestamps are the same prioritise low block_num
        }
        return x > y;  // when block_num are the same preserve identity
    }
};

struct AnchorOlderThan : public std::function<bool(std::shared_ptr<Anchor>, std::shared_ptr<Anchor>)> {
    bool operator()(const std::shared_ptr<Anchor>& x, const std::shared_ptr<Anchor>& y) const {
        if (x->timestamp != y->timestamp) {
            return x->timestamp < y->timestamp;  // prefer smaller timestamp
        }
        if (x->block_num != y->block_num) {
            return x->block_num < y->block_num;  // when timestamps are the same prioritise low block_num
        }
        return x < y;  // when block_num are the same preserve identity
    }
};

struct BlockOlderThan : public std::function<bool(BlockNum, BlockNum)> {
    bool operator()(const BlockNum& x, const BlockNum& y) const { return x < y; }
};

// Priority queue types

// For persisted links, those with the lower block numbers get evicted first. This means that more recently persisted
// links are preferred.
// For non-persisted links, those with the max block numbers get evicted first. This is to prevent "holes" in the
// block numbers that may cause inability to insert headers in the ascending order of their block numbers.

// We need a queue for persisted links to
// - get older links to evict when we need to free memory
// - get parent header when we need to verify a new one
// using OldestFirstLinkQueue = std::multimap<BlockNum, std::shared_ptr<Link>, BlockOlderThan>;

}  // namespace silkworm
template <>
struct MbpqKey<std::shared_ptr<silkworm::Link>> {                                               // extract key type and value
    using type = silkworm::BlockNum;                                                            // type of the key
    static type value(const std::shared_ptr<silkworm::Link>& link) { return link->block_num; }  // value of the key
};
namespace silkworm {  // reopen namespace

// A queue of older links to evict when we need to free memory
using OldestFirstLinkMap = MapBasedPriorityQueue<std::shared_ptr<Link>, BlockOlderThan>;

// A queue of younger links to get the next link to process
using OldestFirstLinkQueue = SetBasedPriorityQueue<std::shared_ptr<Link>, LinkOlderThan>;

// We need a queue for anchors to get anchors in reverse order respect to timestamp
// (that is the time at which we asked peers for ancestor of the anchor)
using OldestFirstAnchorQueue = SetBasedPriorityQueue<std::shared_ptr<Anchor>, AnchorOlderThan>;

// Maps to get a link or an anchor by hash
using LinkMap = std::map<Hash, std::shared_ptr<Link>>;      // hash = link hash
using AnchorMap = std::map<Hash, std::shared_ptr<Anchor>>;  // hash = anchor *parent* hash

/* We can improve encapsulation:
 * AnchorMap key is the anchor parent hash, note 'parent', so it is better to encapsulate this knowledge in a class,
 * so we can write anchor_map.add(anchor) in place of anchor_map[anchor->parent_hash] = anchor
 * Also anchorQueue and anchorMap should be encapsulated because if one change an anchor then anchorQueue must be
 * fixed (= re-ordered). For this purpose assess boost::multi-index-container to replace the queue + map pair
 */

// Other containers
using LinkList = std::vector<std::shared_ptr<Link>>;
using LinkLIFOQueue = std::stack<std::shared_ptr<Link>>;

using Headers = std::vector<std::shared_ptr<BlockHeader>>;

inline BlockHeader& header_at(Headers::iterator it) { return **it; }

inline BlockHeader& header_at(Headers::reverse_iterator it) { return **it; }

inline const BlockHeader& header_at(Headers::const_iterator it) { return **it; }

inline const BlockHeader& header_at(Headers::const_reverse_iterator it) { return **it; }

struct Segment;  // forward declaration

// A list of (possibly unrelated) headers
// It arrives from remote peers, it is divided in Segments, and each Segment will be processed alone; each Segment has
// only references to the headers in the list so for safety reason each Segment has also a shared_ptr to the HeaderList
// so one instance of HeaderList remains alive whenever there is at least one Segment that uses it
struct HeaderList : std::enable_shared_from_this<HeaderList> {
  public:
    using Header_Ref = std::vector<BlockHeader>::const_iterator;

    static std::shared_ptr<HeaderList> make(const std::vector<BlockHeader>& headers) {
        return std::shared_ptr<HeaderList>(new HeaderList(headers));
    }

    std::tuple<std::vector<Segment>, Penalty> split_into_segments();  // the core functionality of HeaderList

    std::vector<BlockHeader>& headers() { return headers_; }

  private:
    // ctor is private because instances need to stay in the heap, use the provided make() method to create an instance
    explicit HeaderList(std::vector<BlockHeader> headers) : headers_(std::move(headers)) {}

    std::vector<BlockHeader> headers_;

    std::vector<Header_Ref> to_ref() {
        std::vector<Header_Ref> refs;
        for (auto i = headers_.begin(); i < headers_.end(); ++i) refs.emplace_back(i);
        return refs;
    }

    static std::tuple<bool, Penalty> child_parent_validity(Header_Ref child, Header_Ref parent) {
        if (parent->number + 1 != child->number) return {false, Penalty::kWrongChildBlockHeightPenalty};
        return {true, kNoPenalty};
    }

    static std::tuple<bool, Penalty> children_parent_validity(const std::vector<Header_Ref>& children, Header_Ref parent) {
        for (auto& child : children) {
            auto [valid, penalty] = child_parent_validity(child, parent);
            if (!valid) return {false, penalty};
        }
        return {true, Penalty::kNoPenalty};
    }
};

// Segment, a sequence of headers connected to one another (with parent-hash relationship),
// without any branching, ordered from high block number to lower block number, from children to parents
struct Segment
    : public std::vector<HeaderList::Header_Ref> {  // pointers/iterators to the headers that belongs to this segment

    explicit Segment(std::shared_ptr<HeaderList> line) : line_(std::move(line)) {}

    void push_back(const HeaderList::Header_Ref& val) {
        SILKWORM_ASSERT(empty() || back()->number == val->number + 1);  // also back()->parent_hash == val->hash() but expensive
        std::vector<HeaderList::Header_Ref>::push_back(val);
    }

    // remove Header_Ref from the segment with number greater than the given one
    void remove_headers_higher_than(BlockNum max) {
        std::erase_if(*this, [max](const HeaderList::Header_Ref& header) {
            return header->number > max;
        });
    }

    HeaderList::Header_Ref max_header() const { return front(); }
    HeaderList::Header_Ref lowest_header() const { return back(); }

    using Slice = std::span<const HeaderList::Header_Ref>;  // a Segment slice

    Slice slice(size_t start, size_t end) const {
        return {data() + start, data() + end};
    }

  protected:
    std::shared_ptr<HeaderList> line_;  // all the headers
};

}  // namespace silkworm
