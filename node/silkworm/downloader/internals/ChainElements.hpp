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

#ifndef SILKWORM_CHAINELEMENTS_HPP
#define SILKWORM_CHAINELEMENTS_HPP

#include <map>
#include <queue>
#include <set>
#include <vector>

#include "DbTx.hpp"
#include "types.hpp"

namespace silkworm {

// Auxiliary types needed to implement WorkingChain

// A link corresponds to a block header, links are connected to each other by reverse of parentHash relation
struct Link {
    std::shared_ptr<BlockHeader> header;        // Header to which this link point to
    BlockNum blockHeight;                       // Block height of the header, repeated here for convenience (remove?)
    Hash hash;                                  // Hash of the header
    std::vector<std::shared_ptr<Link>> next;    // Reverse of parentHash / Allows iteration over links in ascending block height order
    bool persisted;                             // Whether this link comes from the database record
    bool preverified;                           // Ancestor of pre-verified header
    int idx;                                    // Index in the heap (used by Go binary heap impl, remove?)

    Link(BlockHeader h, bool persisted_) {
        blockHeight = h.number;
        hash = h.hash();
        header = std::make_shared<BlockHeader>(std::move(h));
        persisted = persisted_;
    }

    void remove_child(std::shared_ptr<Link> child) {
        std::remove_if(next.begin(), next.end(), [child](auto& link) {return (link->hash == child->hash);});
    }
};

// An anchor is the bottom of a chain bundle that consists of one anchor and some chain links.
struct Anchor {
    Hash parentHash;                            // Hash of the header this anchor can be connected to (to disappear)
    BlockNum blockHeight;                       // block height of the anchor
    uint64_t timestamp;                         // Zero when anchor has just been created, otherwise timestamps when timeout on this anchor request expires
    int timeouts;                               // Number of timeout that this anchor has experiences - after certain threshold, it gets invalidated
    std::vector<std::shared_ptr<Link>> links;   // Links attached immediately to this anchor
    PeerId peerId;

    Anchor(const BlockHeader& header, PeerId p) {
        parentHash = header.parent_hash;
        blockHeight = header.number;
        timestamp = 0;
        peerId = p;
    }

    void remove_child(std::shared_ptr<Link> child) {
        std::remove_if(links.begin(), links.end(), [child](auto& link) {return (link->hash == child->hash);});
    }
};

// Binary relations to use in priority queues
struct Link_Older_Than: public std::binary_function<std::shared_ptr<Link>, std::shared_ptr<Link>, bool>
{
    bool operator()(const std::shared_ptr<Link>& x, const std::shared_ptr<Link>& y) const
    { return x->blockHeight < y->blockHeight; }
};

struct Link_Younger_Than: public std::binary_function<std::shared_ptr<Link>, std::shared_ptr<Link>, bool>
{
    bool operator()(const std::shared_ptr<Link>& x, const std::shared_ptr<Link>& y) const
    { return x->blockHeight > y->blockHeight; }
};

struct Anchor_Older_Than: public std::binary_function<std::shared_ptr<Anchor>, std::shared_ptr<Anchor>, bool>
{
    bool operator()(const std::shared_ptr<Anchor>& x, const std::shared_ptr<Anchor>& y) const
    { return x->timestamp < y->timestamp; }
};

// Priority queue types
using Oldest_First_Link_Queue  = std::priority_queue<std::shared_ptr<Link>,
                                                     std::vector<std::shared_ptr<Link>>,
                                                     Link_Older_Than>;

using Youngest_First_Link_Queue = std::priority_queue<std::shared_ptr<Link>,
                                                      std::vector<std::shared_ptr<Link>>,
                                                      Link_Younger_Than>;

using Oldest_First_Anchor_Queue = std::priority_queue<std::shared_ptr<Anchor>,
                                                      std::vector<std::shared_ptr<Anchor>>,
                                                      Anchor_Older_Than>;

// Maps
using Link_Map = std::map<Hash,std::shared_ptr<Link>>;     // hash = link hash
using Anchor_Map = std::map<Hash,std::shared_ptr<Anchor>>; // hash = anchor *parent* hash

// Lists
using Link_List = std::vector<std::shared_ptr<Link>>;

struct Segment; // forward declaration

// A list of (possibly unrelated) headers
struct HeaderList: std::enable_shared_from_this<HeaderList> {
public:
    using Header_Ref = std::vector<BlockHeader>::const_iterator; // todo: check what is better among const_iterator or shared_ptr or hash

    static std::shared_ptr<HeaderList> make(const std::vector<BlockHeader>& headers) {
        return std::shared_ptr<HeaderList>(new HeaderList(headers));
    }

    auto split_into_segments() -> std::tuple<std::vector<Segment>, Penalty>;

    std::vector<BlockHeader>& headers() {return headers_;}

private:
    HeaderList(std::vector<BlockHeader> headers): headers_(std::move(headers)) {}

    std::vector<BlockHeader> headers_;

    std::vector<Header_Ref> to_ref();

    std::tuple<bool,Penalty> static childParentValidity(Header_Ref child, Header_Ref parent);

    std::tuple<bool,Penalty> static childrenParentValidity(const std::vector<Header_Ref>& children, Header_Ref parent);
};


// Segment, a sequence of headers connected to one another (with parent-hash relationship),
// without any branching, ordered from high block number to lower block number
struct Segment:
        public std::vector<HeaderList::Header_Ref> { // pointers/iterators to the headers that belongs to this segment

    Segment(std::shared_ptr<HeaderList> line): line_(line) {}

    void push_back (const HeaderList::Header_Ref& val) {
        assert(size() == 0 || back()->number == val->number + 1); // also back()->parent_hash == val->hash() (expensive test)
        std::vector<HeaderList::Header_Ref>::push_back(val);
    }

    HeaderList::Header_Ref lowest_header() const {return back();}

    using Slice = gsl::span<const HeaderList::Header_Ref>; // a Segment slice

    Slice slice(size_t start, size_t end) const { return Slice(*this).subspan(start, end); } // with c++20 it can be implemented as: return Slice(begin() + start, begin() + end);

protected:
    //std::vector<something> headersRaw; // todo: do we need this?
    std::shared_ptr<HeaderList> line_; // all the headers
};

}

#endif //SILKWORM_CHAINELEMENTS_HPP
