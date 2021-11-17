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

#include "working_chain.hpp"

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/log.hpp>

#include "random_number.hpp"

namespace silkworm {

class segment_cut_and_paste_error : public std::logic_error {
  public:
    segment_cut_and_paste_error() : std::logic_error("segment cut&paste error, unknown reason") {}
    explicit segment_cut_and_paste_error(const std::string& reason) : std::logic_error(reason) {}
};

WorkingChain::WorkingChain()
    : highestInDb_(0), topSeenHeight_(0), preverifiedHashes_{&PreverifiedHashes::none}, seenAnnounces_(1000) {}

BlockNum WorkingChain::highest_block_in_db() const { return highestInDb_; }

void WorkingChain::top_seen_block_height(BlockNum n) { topSeenHeight_ = n; }

BlockNum WorkingChain::top_seen_block_height() const { return topSeenHeight_; }

bool WorkingChain::in_sync() const {
    return highestInDb_ >= preverifiedHashes_->height && topSeenHeight_ > 0 && highestInDb_ >= topSeenHeight_;
}

std::string WorkingChain::human_readable_status() const {
    return std::to_string(anchors_.size()) + " anchors, " + std::to_string(links_.size()) + " links";
}

std::string WorkingChain::human_readable_verbose_status() const {
    std::string verbose_status;
    verbose_status += std::to_string(links_.size()) + " links, " + std::to_string(anchors_.size()) + " anchors (";
    for (auto& anchor : anchors_) {
        verbose_status += std::to_string(anchor.second->blockHeight) + ",";
    }
    verbose_status += ")";
    return verbose_status;
}

std::vector<Announce>& WorkingChain::announces_to_do() { return announcesToDo_; }

void WorkingChain::add_bad_headers(std::set<Hash> bads) {
    badHeaders_.insert(bads.begin(), bads.end());  // todo: use set_union or merge?
}

// See Erigon RecoverFromDb
void WorkingChain::recover_initial_state(Db::ReadOnlyAccess::Tx& tx) {
    reduce_persisted_links_to(0);  // drain persistedLinksQueue and remove links

    tx.read_headers_in_reverse_order(persistent_link_limit, [this](BlockHeader&& header) {
        this->add_header_as_link(header, true);  // todo: optimize add_header_as_link to use Header&&
    });

    // highestInDb_ = tx.read_stage_progress(db::stages::kHeadersKey); // will be done by sync_with
}

void WorkingChain::sync_current_state(BlockNum highest_in_db) { highestInDb_ = highest_in_db; }

Headers WorkingChain::withdraw_stable_headers() {
    Headers stable_headers;

    LinkList links_in_future;  // here we accumulate links that fail validation as "in the future"

    while (!insertList_.empty()) {
        // Make sure long insertions do not appear as a stuck stage headers
        log::InfoChannel() << "WorkingChain: persisting headers (on top of " << highestInDb_ << ")\n";

        // Choose a link at top
        auto link = insertList_.top();  // is the last added
        if (link->blockHeight <= preverifiedHashes_->height && !link->preverified) {
            break;  // header should be preverified, but not yet, try again later
        }

        insertList_.pop();

        bool skip = false;
        if (!link->preverified) {
            if (contains(badHeaders_, link->hash))
                skip = true;
            else if (auto error = ConsensusProto::verify(*link->header); error == ConsensusProto::VERIFICATION_ERROR) {
                if (error == ConsensusProto::FUTURE_BLOCK) {
                    links_in_future.push_back(link);
                    log::WarningChannel() << "WorkingChain: added future link,"
                                          << " hash=" << link->hash << " height=" << link->blockHeight
                                          << " timestamp=" << link->header->timestamp << ")\n";
                    continue;
                } else {
                    skip = true;
                }
            } else {
                if (seenAnnounces_.get(link->hash)) {
                    seenAnnounces_.remove(link->hash);
                    announcesToDo_.push_back({link->hash, link->blockHeight});
                }
            }
        }
        if (contains(links_, link->hash)) {
            linkQueue_.erase(link);
        }
        if (skip) {
            links_.erase(link->hash);
            continue;
        }

        stable_headers.push_back(link->header);  // will be persisted by PersistedChain

        if (link->blockHeight > highestInDb_) {
            highestInDb_ = link->blockHeight;
        }

        link->persisted = true;
        link->header = nullptr;  // drop header reference to free memory, as we won't need it anymore
        persistedLinkQueue_.push(link);
        if (!link->next.empty()) {
            push_all(insertList_, link->next);
        }
    }

    reduce_persisted_links_to(persistent_link_limit);

    if (!links_in_future.empty()) {
        push_all(insertList_, links_in_future);
        links_in_future.clear();
    }

    // return highestInDb_ >= preverifiedHeight_ &&
    //        topSeenHeight_ > 0 &&
    //        highestInDb_ >= topSeenHeight_;
    return stable_headers;  // RVO
}

// reduce persistedLinksQueue and remove links
void WorkingChain::reduce_persisted_links_to(size_t limit) {
    while (persistedLinkQueue_.size() > limit) {
        auto link = persistedLinkQueue_.top();
        persistedLinkQueue_.pop();

        links_.erase(link->hash);
    }
}

// Note: Erigon's HeadersForward is implemented in OutboundGetBlockHeaders message

/*
 * Skeleton query.
 * Request "seed" headers that can became anchors.
 * It requests N headers starting at highestInDb with step = stride up to topSeenHeight.
 * Note that skeleton queries are only generated when current number of non-persisted chain bundles (which is equal
 * to number of anchors) is below certain threshold (currently 16). This is because processing an answer to a skeleton
 * request would normally create up to 192 new anchors, and then it will take some time for the second type of queries
 * (anchor extension queries) to fill the gaps and so reduce the number of anchors.
 */
std::optional<GetBlockHeadersPacket66> WorkingChain::request_skeleton() {
    BlockNum lowest_anchor = lowest_unsaved_anchor_from(topSeenHeight_);

    BlockNum length = (lowest_anchor - highestInDb_) / stride;

    if (length > max_len) length = max_len;
    if (length == 0) return std::nullopt;

    GetBlockHeadersPacket66 packet;
    packet.requestId = RANDOM_NUMBER.generate_one();
    packet.request.origin = highestInDb_ + stride;
    packet.request.amount = length;
    packet.request.skip = stride;
    packet.request.reverse = false;

    return {packet};
}

size_t WorkingChain::anchors_within_range(BlockNum max) {
    return static_cast<size_t>(
        as_range::count_if(anchors_, [&max](const auto& anchor) { return anchor.second->blockHeight < max; }));
}

BlockNum WorkingChain::lowest_unsaved_anchor_from(BlockNum top_bn) {
    BlockNum lowest_bn = top_bn;
    for (const auto& anchor : anchors_) {
        if (anchor.second->blockHeight > highestInDb_ && anchor.second->blockHeight < lowest_bn) {
            lowest_bn = anchor.second->blockHeight;
        }
    }
    return lowest_bn;
}

/*
 * Anchor extension query.
 * The function uses an auxiliary data structure, anchorQueue to decide which anchors to select for queries first.
 * anchorQueue is a priority queue of anchors, priorities by the timestamp of latest anchor extension query issued
 * for an anchor. Anchors for which the extension queries were not issued for the longest time, come on top.
 * The anchor on top gets repeated query, but only after certain timeout (currently 5 second) since the last query,
 * and only of the anchor still exists (i.e. it has not been extended yet). Also, if an anchor gets certain number
 * of extension requests issued (currently 10), but without luck of being extended, that anchor gets invalidated,
 * and all its descendants get deleted from consideration (invalidate_anchor function). This would happen if anchor
 * was "fake", i.e. it corresponds to a header without existing ancestors.
 */
auto WorkingChain::request_more_headers(time_point_t time_point, seconds_t timeout)
    -> std::tuple<std::optional<GetBlockHeadersPacket66>, std::vector<PeerPenalization>> {
    using std::nullopt;

    if (anchorQueue_.empty()) {
        log::DebugChannel() << "WorkingChain, no more headers to request: empty anchor queue";
        return {};
    }

    std::vector<PeerPenalization> penalties;
    while (!anchorQueue_.empty()) {
        auto anchor = anchorQueue_.top();

        if (!contains(anchors_, anchor->parentHash)) {
            anchorQueue_.pop();  // anchor disappeared (i.e. it became link as per our request) or unavailable,
            continue;            // normal condition, pop from the queue and move on
        }

        if (anchor->timestamp > time_point) {
            return {nullopt, penalties};  // anchor not ready for "extend" re-request yet
        }

        if (anchor->timeouts < 10) {
            anchor->update_timestamp(time_point + timeout);
            anchorQueue_.fix();

            GetBlockHeadersPacket66 packet{RANDOM_NUMBER.generate_one(), {anchor->blockHeight, max_len, 0, true}};
            // todo: why we use blockHeight in place of parentHash?
            return {packet, penalties};  // try (again) to extend this anchor
        } else {
            // ancestors of this anchor seem to be unavailable, invalidate and move on
            log::WarningChannel() << "WorkingChain: invalidating anchor for suspected unavailability, "
                                  << "height=" << anchor->blockHeight << "\n";
            invalidate(*anchor);
            anchors_.erase(anchor->parentHash);
            anchorQueue_.pop();
            penalties.emplace_back(Penalty::AbandonedAnchorPenalty, anchor->peerId);
        }
    }

    return {nullopt, penalties};
}

void WorkingChain::invalidate(Anchor& anchor) {
    auto link_to_remove = anchor.links;
    while (!link_to_remove.empty()) {
        auto removal = link_to_remove.back();
        link_to_remove.pop_back();
        links_.erase(removal->hash);
        linkQueue_.erase(removal);
        move_at_end(link_to_remove, removal->next);
    }
}

// SaveExternalAnnounce - does mark hash as seen in external announcement, only such hashes will broadcast further after
void WorkingChain::save_external_announce(Hash h) {
    seenAnnounces_.put(h, 0);  // we ignore the value in the map (zero here), we only need the key
}

void WorkingChain::request_nack(const GetBlockHeadersPacket66& packet) {
    std::shared_ptr<Anchor> anchor;

    log::WarningChannel() << "WorkingChain: restoring some timestamp due to request nack\n";

    if (std::holds_alternative<Hash>(packet.request.origin)) {
        Hash hash = std::get<Hash>(packet.request.origin);
        auto anchor_it = anchors_.find(hash);
        if (anchor_it != anchors_.end()) anchor = anchor_it->second;
    } else {
        BlockNum bn = std::get<BlockNum>(packet.request.origin);
        for (const auto& p : anchors_) {
            if (p.second->blockHeight == bn) {  // this search it is burdensome but should rarely occur
                anchor = p.second;
                break;
            }
        }
    }

    if (anchor == nullptr) return;  // not found

    anchor->restore_timestamp();
    anchorQueue_.fix();
}

bool WorkingChain::has_link(Hash hash) { return (links_.find(hash) != links_.end()); }

auto WorkingChain::find_bad_header(const std::vector<BlockHeader>& headers) -> bool {
    return as_range::any_of(headers, [&](const BlockHeader& header) -> bool {
        const Hash& hash{header.hash()};
        return contains(badHeaders_, hash);
    });
}

auto WorkingChain::accept_headers(const std::vector<BlockHeader>& headers, PeerId peerId)
    -> std::tuple<Penalty, RequestMoreHeaders> {
    bool requestMoreHeaders = false;

    if (find_bad_header(headers)) return {Penalty::BadBlockPenalty, requestMoreHeaders};

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();  // todo: Erigon here pass also headerRaw

    if (penalty != Penalty::NoPenalty) return {penalty, requestMoreHeaders};

    for (auto& segment : segments) {
        requestMoreHeaders |= process_segment(segment, false, peerId);
    }

    return {Penalty::NoPenalty, requestMoreHeaders};
}

auto HeaderList::to_ref() -> std::vector<Header_Ref> {
    std::vector<Header_Ref> refs;
    for (Header_Ref i = headers_.begin(); i < headers_.end(); i++) refs.push_back(i);
    return refs;
}

std::tuple<bool, Penalty> HeaderList::childParentValidity(Header_Ref child, Header_Ref parent) {
    if (parent->number + 1 != child->number) return {false, Penalty::WrongChildBlockHeightPenalty};
    return {true, NoPenalty};
}

std::tuple<bool, Penalty> HeaderList::childrenParentValidity(const std::vector<Header_Ref>& children,
                                                             Header_Ref parent) {
    for (auto& child : children) {
        auto [valid, penalty] = childParentValidity(child, parent);
        if (!valid) return {false, penalty};
    }
    return {true, Penalty::NoPenalty};
}

/*
 * SplitIntoSegments converts message containing headers into a collection of chain segments.
 * A message received from a peer may contain a collection of disparate headers (for example, in a response to the
 * skeleton query), or any branched chain bundle. So it needs to be split into chain segments.
 * SplitIntoSegments takes a collection of headers and return a collection of chain segments in a specific order.
 * This order is the ascending order of the lowest block height in the segment.
 * There may be many possible ways to split a chain bundle into segments, we choose one that is simple and that assures
 * this properties:
 *    - segments form a partial order
 *    - whatever part of the chain that becomes canonical it is not necessary to redo the process of division into
 * segments
 */
auto HeaderList::split_into_segments() -> std::tuple<std::vector<Segment>, Penalty> {
    std::vector<Header_Ref> headers = to_ref();
    as_range::sort(headers, [](auto& h1, auto& h2) {
        return h1->number > h2->number;
    });  // sort headers from the highest block height to the lowest

    std::vector<Segment> segments;
    std::map<Hash, size_t> segmentMap;
    std::map<Hash, std::vector<Header_Ref>> childrenMap;
    std::set<Hash> dedupMap;
    size_t segmentIdx = 0;

    for (auto& header : headers) {
        Hash header_hash = header->hash();

        if (contains(dedupMap, header_hash)) return {{}, Penalty::DuplicateHeaderPenalty};

        dedupMap.insert(header_hash);
        auto children = childrenMap[header_hash];
        auto [valid, penalty] = HeaderList::childrenParentValidity(children, header);
        if (!valid) return {{}, penalty};

        if (children.size() == 1) {
            // Single child, extract segmentIdx
            segmentIdx = segmentMap[header_hash];
        } else {
            // No children, or more than one child, create new segment
            segmentIdx = segments.size();
            segments.emplace_back(shared_from_this());  // add a void segment
        }

        segments[segmentIdx].push_back(header);
        // segments[segmentIdx].headersRaw.push_back(headersRaw[i]); // todo: do we need this?

        segmentMap[header->parent_hash] = segmentIdx;

        auto& siblings = childrenMap[header->parent_hash];
        siblings.push_back(header);
    }

    return {segments, Penalty::NoPenalty};
}

auto WorkingChain::process_segment(const Segment& segment, bool is_a_new_block, PeerId peerId) -> RequestMoreHeaders {
    auto [foundAnchor, start] = find_anchor(segment);
    auto [foundTip, end] = find_link(segment, start);

    if (end == 0) {
        log::DebugChannel() << "WorkingChain: duplicate segment\n";
        // If duplicate segment is extending from the anchor, the anchor needs to be deleted,
        // otherwise it will keep producing requests that will be found duplicate
        if (foundAnchor) remove_anchor(segment[start]->hash());  // note: hash and not parent_hash
        return false;
    }

    auto lowest_header = segment.back();
    auto height = lowest_header->number;

    if (is_a_new_block || seenAnnounces_.get(Hash(lowest_header->hash())) != nullptr) {
        if (height > topSeenHeight_) topSeenHeight_ = height;
    }

    auto startNum = segment[start]->number;
    auto endNum = segment[end - 1]->number;

    // Segment::Slice segment_slice{segment.begin()+start, segment.begin()+end};  // require c++20 span
    Segment::Slice segment_slice = segment.slice(start, end);

    std::string op;
    bool requestMore = false;
    try {
        if (foundAnchor) {
            if (foundTip) {
                op = "connect";
                connect(segment_slice);
            } else {  // ExtendDown
                op = "extend down";
                requestMore = extend_down(segment_slice);
            }
        } else if (foundTip) {
            if (end > 0) {  // ExtendUp
                op = "extend up";
                extend_up(segment_slice);
            }
        } else {  // NewAnchor
            op = "new anchor";
            requestMore = new_anchor(segment_slice, peerId);
        }
        log::DebugChannel() << "Segment: " << op << " start=" << startNum << " end=" << endNum << "\n";
    } catch (segment_cut_and_paste_error& e) {
        log::DebugChannel() << "Segment: " << op << " failure, reason:" << e.what() << "\n";
        return false;
    }

    reduce_links_to(link_limit);

    // select { case hd.DeliveryNotify <- struct{}{}: default: } // todo: translate

    return requestMore /* && hd.requestChaining */;  // todo: translate requestChaining
}

void WorkingChain::reduce_links_to(size_t limit) {
    if (linkQueue_.size() <= limit) return;  // does nothing

    log::DebugChannel() << "LinkQueue: too many links, cutting down from " << linkQueue_.size() << " to " << link_limit
                        << "\n";

    while (linkQueue_.size() > limit) {
        auto link = linkQueue_.top();
        linkQueue_.pop();
        links_.erase(link->hash);
        // delete not needed, using shared_ptr

        auto parentLink_i = links_.find(link->header->parent_hash);
        if (parentLink_i != links_.end()) parentLink_i->second->remove_child(link);

        auto anchor_i = anchors_.find(link->header->parent_hash);
        if (anchor_i != anchors_.end()) anchor_i->second->remove_child(link);
    }
}

// find_anchors tries to finds the highest link the in the new segment that can be attached to an existing anchor
auto WorkingChain::find_anchor(const Segment& segment) -> std::tuple<Found, Start> {  // todo: do we need a span?
    for (size_t i = 0; i < segment.size(); i++)
        if (anchors_.find(segment[i]->hash()) != anchors_.end())  // todo: hash() compute the value,
            return {true, i};                                     // do we need to cache it?

    return {false, 0};
}

// find_link find the highest existing link (from start) that the new segment can be attached to
auto WorkingChain::find_link(const Segment& segment, size_t start)
    -> std::tuple<Found, End> {  // todo: End o Header_Ref?
    auto duplicate_link = get_link(segment[start]->hash());
    if (duplicate_link) return {false, 0};
    for (size_t i = start; i < segment.size(); i++) {
        // Check if the header can be attached to any links
        auto attaching_link = get_link(segment[i]->parent_hash);
        if (attaching_link) return {true, i + 1};  // return the ordinal of the next link
    }
    return {false, segment.size()};
}

auto WorkingChain::get_link(const Hash& hash) -> std::optional<std::shared_ptr<Link>> {
    if (auto it = links_.find(hash); it != links_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void WorkingChain::connect(Segment::Slice segment_slice) {  // throw segment_cut_and_paste_error
    using std::to_string;

    // the 3 following blocks are extend_up
    auto link_header = *segment_slice.rbegin();  // lowest header
    auto attachment_link = get_link(link_header->parent_hash);
    if (!attachment_link)
        throw segment_cut_and_paste_error("segment cut&paste error, connect attachment link not found for " +
                                          to_hex(link_header->parent_hash));
    if (attachment_link.value()->preverified && !attachment_link.value()->next.empty())
        throw segment_cut_and_paste_error("segment cut&paste error, cannot connect to preverified link " +
                                          to_string(attachment_link.value()->blockHeight) + " with children");

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link.value();
    for (auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverifiedHashes_->contains(link->hash)) mark_as_preverified(link);
    }

    // todo: modularize this, his block is the same in extend_down
    auto header_to_anchor = *segment_slice.begin();    // highest header
    auto a = anchors_.find(header_to_anchor->hash());  // header_to_anchor->hash() == anchor.parent_hash
    bool attaching = a != anchors_.end();
    if (!attaching)
        throw segment_cut_and_paste_error("segment cut&paste error, connect attachment anchors not found for " +
                                          to_hex(header_to_anchor->hash()));

    // todo: this block is the same in extend_down
    auto anchor = a->second;
    bool anchor_preverified =
        as_range::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });

    anchors_.erase(anchor->parentHash);  // Anchor is removed from the map, but not from the anchorQueue
    // This is because it is hard to find the index under which the anchor is stored in the anchorQueue
    // But removal will happen anyway, in th function request_more_headers, if it disappears from the map

    // todo: this block is also in "extend_down" method
    prev_link->next = std::move(anchor->links);
    anchor->links.clear();
    if (anchor_preverified) mark_as_preverified(prev_link);  // Mark the entire segment as preverified

    if (contains(badHeaders_, attachment_link.value()->hash)) {
        invalidate(*anchor);
        // todo: add & return penalties: []PenaltyItem := append(penalties, PenaltyItem{Penalty: AbandonedAnchorPenalty,
        // PeerID: anchor.peerID})
    } else if (attachment_link.value()->persisted) {
        auto link = links_.find(link_header->hash());
        if (link != links_.end())  // todo: Erigon code assume true always, check!
            insertList_.push(link->second);
    }
}

auto WorkingChain::extend_down(Segment::Slice segment_slice) -> RequestMoreHeaders {
    // throw segment_cut_and_paste_error

    auto anchor_header = *segment_slice.begin();  // highest header
    auto a = anchors_.find(anchor_header->hash());
    bool attaching = a != anchors_.end();
    if (!attaching)
        throw segment_cut_and_paste_error("segment cut&paste error, extend down attachment anchors not found for " +
                                          to_hex(anchor_header->hash()));

    auto old_anchor = a->second;
    bool anchor_preverified =
        as_range::any_of(old_anchor->links, [](const auto& link) -> bool { return link->preverified; });

    anchors_.erase(old_anchor->parentHash);  // Anchor is removed from the map, but not from the anchorQueue
    // This is because it is hard to find the index under which the anchor is stored in the anchorQueue
    // But removal will happen anyway, in th function RequestMoreHeaders, if it disapppears from the map

    // todo: modularize this block in "add_anchor_if_not_present"
    auto new_anchor_header = *segment_slice.rbegin();  // lowest header
    std::shared_ptr<Anchor> new_anchor;
    a = anchors_.find(new_anchor_header->parent_hash);
    bool pre_existing = a != anchors_.end();
    if (!pre_existing) {
        new_anchor = std::make_shared<Anchor>(*new_anchor_header, old_anchor->peerId);
        if (new_anchor->blockHeight > 0) {
            anchors_[new_anchor_header->parent_hash] = new_anchor;
            anchorQueue_.push(new_anchor);
        }
    } else {
        new_anchor = a->second;
    }

    // todo: modularize this block
    // Iterate over headers backwards (from parents towards children)
    // Add all headers in the segments as links to this anchor
    std::shared_ptr<Link> prev_link;
    for (auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (!prev_link)
            new_anchor->links.push_back(link);  // add the link chain in the anchor
        else
            prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverifiedHashes_->contains(link->hash)) mark_as_preverified(link);
    }

    // todo: this block is also in "connect" method
    prev_link->next = std::move(old_anchor->links);
    old_anchor->links.clear();
    if (anchor_preverified) mark_as_preverified(prev_link);  // Mark the entire segment as preverified

    return !pre_existing;
}

void WorkingChain::extend_up(Segment::Slice segment_slice) {  // throw segment_cut_and_paste_error
    using std::to_string;

    // Find previous link to extend up with the segment
    auto link_header = *segment_slice.rbegin();  // lowest header
    auto attachment_link = get_link(link_header->parent_hash);
    if (!attachment_link)
        throw segment_cut_and_paste_error("segment cut&paste error, extend up attachment link not found for " +
                                          to_hex(link_header->parent_hash));
    if (attachment_link.value()->preverified && !attachment_link.value()->next.empty())
        throw segment_cut_and_paste_error("segment cut&paste error, cannot extend up from preverified link " +
                                          to_string(attachment_link.value()->blockHeight) + " with children");

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link.value();
    for (auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverifiedHashes_->contains(link->hash)) mark_as_preverified(link);
    }

    if (attachment_link.value()->persisted && !contains(badHeaders_, attachment_link.value()->hash)) {
        auto link = links_.find(link_header->hash());
        if (link != links_.end())  // todo: Erigon code assume true always, check!
            insertList_.push(link->second);
    }
}

auto WorkingChain::new_anchor(Segment::Slice segment_slice, PeerId peerId) -> RequestMoreHeaders {
    // throw segment_cut_and_paste_error
    using std::to_string;

    auto anchor_header = *segment_slice.rbegin();  // lowest header

    // todo: modularize this block in "add_anchor_if_not_present"
    // Add to anchors list if not
    auto a = anchors_.find(anchor_header->parent_hash);
    bool pre_existing = a != anchors_.end();
    std::shared_ptr<Anchor> anchor;
    if (!pre_existing) {
        if (anchor_header->number < highestInDb_)
            throw segment_cut_and_paste_error(
                "segment cut&paste error, new anchor too far in the past: " + to_string(anchor_header->number) +
                ", latest header in db: " + to_string(highestInDb_));
        if (anchors_.size() >= anchor_limit)
            throw segment_cut_and_paste_error("segment cut&paste error, too many anchors: " +
                                              to_string(anchors_.size()) + ", limit: " + to_string(anchor_limit));

        anchor = std::make_shared<Anchor>(*anchor_header, peerId);
        anchors_[anchor_header->parent_hash] = anchor;
        anchorQueue_.push(anchor);
    } else {  // pre-existing
        anchor = a->second;
    }

    // todo: modularize this block
    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link;
    for (auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (!prev_link)
            anchor->links.push_back(link);  // add the link chain in the anchor
        else
            prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverifiedHashes_->contains(link->hash)) mark_as_preverified(link);
    }

    return !pre_existing;
}

auto WorkingChain::add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link> {
    auto link = std::make_shared<Link>(header, persisted);
    links_[link->hash] = link;
    if (persisted)
        persistedLinkQueue_.push(link);
    else
        linkQueue_.push(link);

    return link;
}

void WorkingChain::remove(Anchor& anchor) { remove_anchor(anchor.parentHash); }
void WorkingChain::remove_anchor(const Hash& hash) {
    // Anchor is removed from the map, but not from the anchorQueue
    // This is because it is hard to find the index under which the anchor is stored in the anchorQueue
    // But removal will happen anyway, in the function request_more_headers, if it disappears from the map
    size_t erased = anchors_.erase(hash);
    if (erased == 0) {
        log::WarningChannel() << "WorkingChain: removal of anchor failed, " << to_hex(hash) << " not found\n";
    }
}

// Mark a link and all its ancestors as preverified
void WorkingChain::mark_as_preverified(std::shared_ptr<Link> link) {
    while (link && !link->persisted) {
        link->preverified = true;
        auto parent = links_.find(link->header->parent_hash);
        link = (parent != links_.end() ? parent->second : nullptr);
    }
}

void WorkingChain::set_preverified_hashes(const PreverifiedHashes* preverifiedHashes) {
    preverifiedHashes_ = preverifiedHashes;
}

}  // namespace silkworm
