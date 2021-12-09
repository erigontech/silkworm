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

#ifndef SILKWORM_CHAIN_ELEMENTS_HPP
#define SILKWORM_CHAIN_ELEMENTS_HPP

#include <map>
#include <queue>
#include <set>
#include <stack>
#include <vector>

#include "db_tx.hpp"
#include "priority_queue.hpp"
#include "types.hpp"

namespace silkworm {

// Auxiliary types needed to implement WorkingChain
/*
struct Knot {   // todo: evaluate if Knot can be used as base class for Anchor and Link
                // problem: add_header_as_link() is ok for Link but not for Anchor
    Hash hash;
    std::vector<std::shared_ptr<Knot>> children;    // Reverse of parentHash, allows iteration over links
                                                    // in ascending block height order
    Knot(const BlockHeader& header): hash(header.hash()) {}

    // use this method to remove similar block in methods connect(), extend_up(), extend_down(), new_anchor()
    auto add(Segment::Slice segment_slice, Container& preverifiedHashes) {
        std::shared_ptr<Knot> prev_link = std::make_shared>(this);
        for(auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
            auto header = *h;
            bool persisted = false;
            auto link = add_header_as_link(*header, persisted);
            prev_link->children.push_back(link); // add link as next of the preceding
            prev_link = link;
            if (contains(preverified_hashes_, link->hash))
                mark_as_preverified(link);
        }
    }

    void remove_child(std::shared_ptr<Knot> child) {
        auto to_remove = std::remove_if(children.begin(), children.end(),
                                        [child](auto& link) {return (link->hash == child->hash);});
        children.erase(to_remove, children.end());
    }
};
*/

// A link corresponds to a block header, links are connected to each other by reverse of parentHash relation
struct Link {
    std::shared_ptr<BlockHeader> header;      // Header to which this link point to
    BlockNum blockHeight = 0;                 // Block height of the header, repeated here for convenience (remove?)
    Hash hash;                                // Hash of the header
    std::vector<std::shared_ptr<Link>> next;  // Reverse of parentHash,allows iter.over links in asc. block height order
    bool persisted = false;                   // Whether this link comes from the database record
    bool preverified = false;                 // Ancestor of pre-verified header

    Link(BlockHeader h, bool persisted_) {
        blockHeight = h.number;
        hash = h.hash();  // save computation
        header = std::make_shared<BlockHeader>(std::move(h));
        persisted = persisted_;
    }

    void remove_child(std::shared_ptr<Link> child) {
        auto to_remove =
            std::remove_if(next.begin(), next.end(), [child](auto& link) { return (link->hash == child->hash); });
        next.erase(to_remove, next.end());
    }

    auto find_child(const Hash& h) {
        return std::find_if(next.begin(), next.end(), [h](auto& link) { return (link->hash == h); });
    }

    bool has_child(const Hash& h) { return find_child(h) != next.end(); }
};

// An anchor is the bottom of a chain bundle that consists of one anchor and some chain links.
struct Anchor {
    Hash parentHash;         // Hash of the header this anchor can be connected to (to disappear)
    BlockNum blockHeight;    // block height of the anchor
    time_point_t timestamp;  // Zero when anchor has just been created, otherwise timestamps when timeout on this anchor
                             // request expires
    time_point_t prev_timestamp;  // Used to restore timestamp when a request fails for network reasons
    int timeouts = 0;  // Number of timeout that this anchor has experienced;after certain threshold,it gets invalidated
    std::vector<std::shared_ptr<Link>> links;  // Links attached immediately to this anchor
    PeerId peerId;

    Anchor(const BlockHeader& header, PeerId p) {
        parentHash = header.parent_hash;
        blockHeight = header.number;
        // timestamp = 0; automatically set to unix epoch by the constructor
        peerId = std::move(p);
    }

    void remove_child(std::shared_ptr<Link> child) {
        auto to_remove =
            std::remove_if(links.begin(), links.end(), [child](auto& link) { return (link->hash == child->hash); });
        links.erase(to_remove, links.end());
    }

    auto find_child(const Hash& h) {
        return std::find_if(links.begin(), links.end(), [h](auto& link) { return (link->hash == h); });
    }

    bool has_child(const Hash& h) { return find_child(h) != links.end(); }

    void update_timestamp(time_point_t time_point) {
        prev_timestamp = timestamp;
        timestamp = time_point;
        timeouts++;
    }

    void restore_timestamp() {
        timeouts--;
        timestamp = prev_timestamp;
    }
};

// Binary relations to use in priority queues
struct LinkOlderThan : public std::function<bool(std::shared_ptr<Link>, std::shared_ptr<Link>)> {
    bool operator()(const std::shared_ptr<Link>& x, const std::shared_ptr<Link>& y) const {
        return x->blockHeight < y->blockHeight;
    }
};

struct LinkYoungerThan : public std::function<bool(std::shared_ptr<Link>, std::shared_ptr<Link>)> {
    bool operator()(const std::shared_ptr<Link>& x, const std::shared_ptr<Link>& y) const {
        return x->blockHeight > y->blockHeight;
    }
};

struct AnchorYoungerThan : public std::function<bool(std::shared_ptr<Link>, std::shared_ptr<Link>)> {
    bool operator()(const std::shared_ptr<Anchor>& x, const std::shared_ptr<Anchor>& y) const {
        return x->timestamp != y->timestamp
                   ? x->timestamp > y->timestamp
                   : x->blockHeight >
                         y->blockHeight;  // when timestamps are the same, we prioritise low block height anchors
    }
};

struct BlockOlderThan : public std::function<bool(BlockNum, BlockNum)> {
    bool operator()(const BlockNum& x, const BlockNum& y) const { return x < y; }
};

// Priority queue types

// For persisted links, those with the lower block heights get evicted first. This means that more recently persisted
// links are preferred.
// For non-persisted links, those with the highest block heights get evicted first. This is to prevent "holes" in the
// block heights that may cause inability to insert headers in the ascending order of their block heights.

// We need a queue for persisted links to
// - get older links to evict when we need to free memory
// - get parent header when we need to verify a new one
// using OldestFirstLinkQueue = std::multimap<BlockNum, std::shared_ptr<Link>, BlockOlderThan>;

} // close namespace to define mbpq_key - I do not like this
template <>
struct mbpq_key<std::shared_ptr<Link>> {    // extract key type and value
    using type = BlockNum;   // type of the key
    static type value(const std::shared_ptr<Link>& l) {return l->blockHeight;} // value of the key
};
namespace silkworm { // reopen namespace

using OldestFirstLinkQueue = map_based_priority_queue<std::shared_ptr<Link>, BlockOlderThan>;


// We need a queue for all links to
// - store the links
// - get younger links to evict when we need to free memory
using YoungestFirstLinkQueue = set_based_priority_queue<std::shared_ptr<Link>,
                                                        LinkYoungerThan>;  // c++ set put min at the top

// We need a queue for anchors to get anchors in reverse order respect to timestamp
// (that is the time at which we asked peers for ancestor of the anchor)
using OldestFirstAnchorQueue = heap_based_priority_queue<std::shared_ptr<Anchor>,
                                                         std::vector<std::shared_ptr<Anchor>>,  // inner impl
                                                         AnchorYoungerThan>;  // c++ heap is a max heap
                                                                              // (note that go heap is a min heap)

// Maps
using LinkMap = std::map<Hash, std::shared_ptr<Link>>;      // hash = link hash
using AnchorMap = std::map<Hash, std::shared_ptr<Anchor>>;  // hash = anchor *parent* hash

/* todo: improve encapsulation
 * AnchorMap key is the anchor parent hash, note 'parent', so it is better to encapsulate this knowledge in a class
 * so we can write anchor_map.add(anchor) in place of anchor_map[anchor->parent_hash] = anchor
 * Also anchorQueue and anchorMap should be encapsulated because if one change an anchor then anchorQueue must be
 * fixed (= re-ordered). For this purpose assess boost::multi-index-container to replace the queue + map pair
 */

// Other containers
using LinkList = std::vector<std::shared_ptr<Link>>;
using LinkLIFOQueue = std::stack<std::shared_ptr<Link>>;

using Headers = std::vector<std::shared_ptr<BlockHeader>>;

inline BlockHeader& header_at(Headers::iterator it) { return *it->get(); }
inline BlockHeader& header_at(Headers::reverse_iterator it) { return *it->get(); }
inline const BlockHeader& header_at(Headers::const_iterator it) { return *it->get(); }
inline const BlockHeader& header_at(Headers::const_reverse_iterator it) { return *it->get(); }

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

    auto split_into_segments() -> std::tuple<std::vector<Segment>, Penalty>;  // the core functionality of HeaderList

    std::vector<BlockHeader>& headers() { return headers_; }

  private:
    HeaderList(std::vector<BlockHeader> headers)
        : headers_(std::move(headers)) {}  // private, it needs to stay in the heap,
                                           // use make method to get an instance
    std::vector<BlockHeader> headers_;

    std::vector<Header_Ref> to_ref();

    std::tuple<bool, Penalty> static childParentValidity(Header_Ref child, Header_Ref parent);

    std::tuple<bool, Penalty> static childrenParentValidity(const std::vector<Header_Ref>& children, Header_Ref parent);
};

// Segment, a sequence of headers connected to one another (with parent-hash relationship),
// without any branching, ordered from high block number to lower block number
struct Segment
    : public std::vector<HeaderList::Header_Ref> {  // pointers/iterators to the headers that belongs to this segment

    Segment(std::shared_ptr<HeaderList> line) : line_(line) {}

    void push_back(const HeaderList::Header_Ref& val) {
        assert(empty() ||
               back()->number == val->number + 1);  // also back()->parent_hash == val->hash() (expensive test)
        std::vector<HeaderList::Header_Ref>::push_back(val);
    }

    [[nodiscard]] HeaderList::Header_Ref lowest_header() const { return back(); }

    using Slice = gsl::span<const HeaderList::Header_Ref>;  // a Segment slice

    [[nodiscard]] Slice slice(size_t start, size_t end) const {
        return Slice(*this).subspan(start, end - start);
    }  // with c++20 it can be implemented as: return Slice(begin() + start, begin() + end);

  protected:
    // std::vector<something> headersRaw; // todo: do we need this?
    std::shared_ptr<HeaderList> line_;  // all the headers
};

}  // namespace silkworm

#endif  // SILKWORM_CHAIN_ELEMENTS_HPP
