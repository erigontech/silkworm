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

WorkingChain::WorkingChain(ConsensusEngine engine)
    : highest_in_db_(0),
      top_seen_height_(0),
      preverified_hashes_{&PreverifiedHashes::none},
      seen_announces_(1000),
      consensus_engine_{std::move(engine)},
      chain_state_(
          persisted_link_queue_) {  // Erigon reads them from db, we hope to find them all in the persistent queue
    if (!consensus_engine_) {
        throw std::logic_error("WorkingChain exception, cause: unknown consensus engine");
        // or must the downloader go on and return StageResult::kUnknownConsensusEngine?
    }
}

BlockNum WorkingChain::highest_block_in_db() const { return highest_in_db_; }

void WorkingChain::top_seen_block_height(BlockNum n) { top_seen_height_ = n; }

BlockNum WorkingChain::top_seen_block_height() const { return top_seen_height_; }

bool WorkingChain::in_sync() const {
    return highest_in_db_ >= preverified_hashes_->height && top_seen_height_ > 0 && highest_in_db_ >= top_seen_height_;
}

std::string WorkingChain::human_readable_status() const {
    return std::to_string(links_.size()) + " links, " + std::to_string(anchors_.size()) + " anchors";
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

std::vector<Announce>& WorkingChain::announces_to_do() { return announces_to_do_; }

void WorkingChain::add_bad_headers(const std::set<Hash>& bads) {
    bad_headers_.insert(bads.begin(), bads.end());  // todo: use set_union or merge?
}

// See Erigon RecoverFromDb - todo: check if this method (& persisted_link_queue_) is really useful
void WorkingChain::recover_initial_state(Db::ReadOnlyAccess::Tx& tx) {
    reduce_persisted_links_to(0);  // drain persistedLinksQueue and remove links

    tx.read_headers_in_reverse_order(persistent_link_limit, [this](BlockHeader&& header) {
        this->add_header_as_link(header, true);  // todo: optimize add_header_as_link to use Header&&
    });

    // highest_in_db_ = tx.read_stage_progress(db::stages::kHeadersKey); // will be done by sync_current_state
}

void WorkingChain::sync_current_state(BlockNum highest_in_db) {
    highest_in_db_ = highest_in_db;

    // we also need here all the headers with height == highest_in_db to init chain_state_
    // currently chain_state_ find them in persisted_link_queue_ but it is not clear if it will find them all
}

Headers WorkingChain::withdraw_stable_headers() {
    Headers stable_headers;

    auto initial_highest_in_db = highest_in_db_;
    log::Trace() << "WorkingChain: finding headers to persist on top of " << highest_in_db_;

    LinkList links_in_future;  // here we accumulate links that fail validation as "in the future"

    while (!insert_list_.empty()) {
        // Choose a link at top
        auto link = insert_list_.top();  // connect or extend-up added one (or some if it has siblings)

        // If it is in the pre-verified headers range do not verify it, wait for pre-verification
        if (link->blockHeight <= preverified_hashes_->height && !link->preverified) {
            break;  // header should be pre-verified, but not yet, try again later
        }

        insert_list_.pop();

        // Verify if not
        VerificationResult assessment = Preverified;
        if (!link->preverified) {
            assessment = verify(*link);
        }

        if (assessment == Postpone) {
            links_in_future.push_back(link);
            log::Warning() << "WorkingChain: added future link,"
                           << " hash=" << link->hash << " height=" << link->blockHeight
                           << " timestamp=" << link->header->timestamp << ")";
            continue;
        }

        if (contains(links_, link->hash)) {
            link_queue_.erase(link);
        }

        if (assessment == Skip) {
            links_.erase(link->hash);
            continue;
        }

        // assessment == accept

        // If we received an announcement for this header we must propagate it
        if (seen_announces_.get(link->hash)) {
            seen_announces_.remove(link->hash);
            announces_to_do_.push_back({link->hash, link->blockHeight});
        }

        // Insert in the list of headers to persist
        stable_headers.push_back(link->header);  // will be persisted by PersistedChain

        // Update persisted height, and state
        if (link->blockHeight > highest_in_db_) {
            highest_in_db_ = link->blockHeight;
        }
        link->persisted = true;
        // link->header = nullptr; // we can drop header reference to free memory except that consensus engine may need
        // it
        persisted_link_queue_.push(link);

        // All the headers attached to this can be persisted, let's add them to the queue, this feeds the current loop
        // and cause insertion of headers in ascending order of height
        if (!link->next.empty()) {
            push_all(insert_list_, link->next);
        }

        // Make sure long insertions do not appear as a stuck stage headers
        if (stable_headers.size() % 1000 == 0) {
            log::Info() << "WorkingChain: " << stable_headers.size() << " headers persisted on top of "
                        << initial_highest_in_db << " (cont.)";
        }
    }

    if (!stable_headers.empty()) {
        log::Info() << "WorkingChain: " << stable_headers.size() << " headers persisted on top of "
                    << initial_highest_in_db << " (from " << header_at(stable_headers.begin()).number << " to "
                    << header_at(stable_headers.cbegin()).number << ")";
    }

    // Save memory
    reduce_persisted_links_to(persistent_link_limit);

    // Save for later
    if (!links_in_future.empty()) {
        push_all(insert_list_, links_in_future);
        links_in_future.clear();
    }

    return stable_headers;  // RVO
}

auto WorkingChain::verify(const Link& link) -> VerificationResult {
    if (contains(bad_headers_, link.hash)) return Skip;

    bool with_future_timestamp_check = true;
    auto result = consensus_engine_->validate_block_header(*link.header, chain_state_, with_future_timestamp_check);

    if (result != ValidationResult::kOk) {
        if (result == ValidationResult::kUnknownParent) {
            SILKWORM_ASSERT(false);
        }
        if (result == ValidationResult::kFutureBlock) {
            return Postpone;
        }
        return Skip;
    }

    return Accept;
}

// reduce persistedLinksQueue and remove links
void WorkingChain::reduce_persisted_links_to(size_t limit) {
    while (persisted_link_queue_.size() > limit) {
        auto link = persisted_link_queue_.top();
        persisted_link_queue_.pop();

        links_.erase(link->hash);
    }
}

// Note: Erigon's HeadersForward is implemented in OutboundGetBlockHeaders message

/*
 * Skeleton query.
 * Request "seed" headers that can became anchors.
 * It requests N headers starting at highestInDb + stride up to topSeenHeight.
 * If there is an anchor at height < topSeenHeight this will be the top limit: this way we prioritize the fill of a big
 * hole near the bottom. If the lowest hole is not so big we do not need a skeleton query yet.
 */
std::optional<GetBlockHeadersPacket66> WorkingChain::request_skeleton() {
    BlockNum top = top_seen_height_;
    BlockNum bottom = highest_in_db_ + stride;
    if (top <= bottom) {
        return std::nullopt;
    }

    BlockNum lowest_anchor = lowest_anchor_within_range(bottom, top+1);

    BlockNum length = (lowest_anchor - bottom) / stride;

    if (length > max_len) length = max_len;
    if (length == 0) {
        log::Debug() << "WorkingChain, no need for skeleton request (lowest_anchor = " << lowest_anchor
                     << ", highest_in_db = " << highest_in_db_ << ")";
        return std::nullopt;
    }

    GetBlockHeadersPacket66 packet;
    packet.requestId = RANDOM_NUMBER.generate_one();
    packet.request.origin = bottom;
    packet.request.amount = length;
    packet.request.skip = stride - 1;
    packet.request.reverse = false;

    return {packet};
}

size_t WorkingChain::anchors_within_range(BlockNum max) {
    return static_cast<size_t>(
        as_range::count_if(anchors_, [&max](const auto& anchor) { return anchor.second->blockHeight < max; }));
}

BlockNum WorkingChain::lowest_anchor_within_range(BlockNum bottom, BlockNum top) {
    BlockNum lowest = top;
    for (const auto& anchor : anchors_) {
        if (anchor.second->blockHeight >= bottom && anchor.second->blockHeight < lowest) {
            lowest = anchor.second->blockHeight;
        }
    }
    return lowest;
}

/*
 * Anchor extension query.
 * The function uses an auxiliary data structure, anchorQueue to decide which anchors to select for queries first.
 * anchorQueue is a priority queue of anchors, priorities by the timestamp of the latest anchor extension query issued
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

    if (anchor_queue_.empty()) {
        log::Debug() << "WorkingChain, no more headers to request: empty anchor queue";
        return {};
    }

    std::vector<PeerPenalization> penalties;
    while (!anchor_queue_.empty()) {
        auto anchor = anchor_queue_.top();

        if (!contains(anchors_, anchor->parentHash)) {
            anchor_queue_.pop();  // anchor disappeared (i.e. it became link as per our request) or unavailable,
            continue;             // normal condition, pop from the queue and move on
        }

        if (anchor->timestamp > time_point) {
            return {nullopt, penalties};  // anchor not ready for "extend" re-request yet
        }

        if (anchor->timeouts < 10) {
            anchor->update_timestamp(time_point + timeout);
            anchor_queue_.fix();  // re-sort

            GetBlockHeadersPacket66 packet{
                RANDOM_NUMBER.generate_one(),
                {anchor->blockHeight-1, max_len, 0, true}
            }; // we use blockHeight in place of parentHash to get also ommers if presents

            return {packet, penalties};  // try (again) to extend this anchor
        } else {
            // ancestors of this anchor seem to be unavailable, invalidate and move on
            log::Warning() << "WorkingChain: invalidating anchor for suspected unavailability, "
                           << "height=" << anchor->blockHeight;
            invalidate(*anchor);
            anchors_.erase(anchor->parentHash);
            anchor_queue_.pop();
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
        link_queue_.erase(removal);
        move_at_end(link_to_remove, removal->next);
    }
}

// SaveExternalAnnounce - does mark hash as seen in external announcement, only such hashes will broadcast further after
void WorkingChain::save_external_announce(Hash h) {
    seen_announces_.put(h, 0);  // we ignore the value in the map (zero here), we only need the key
}

void WorkingChain::request_nack(const GetBlockHeadersPacket66& packet) {
    std::shared_ptr<Anchor> anchor;

    log::Warning() << "WorkingChain: restoring some timestamp due to request nack";

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
    anchor_queue_.fix();
}

bool WorkingChain::has_link(Hash hash) { return (links_.find(hash) != links_.end()); }

auto WorkingChain::find_bad_header(const std::vector<BlockHeader>& headers) -> bool {
    return as_range::any_of(headers, [&](const BlockHeader& header) -> bool {
        const Hash& hash{header.hash()};
        return contains(bad_headers_, hash);
    });
}

auto WorkingChain::accept_headers(const std::vector<BlockHeader>& headers, const PeerId& peer_id)
    -> std::tuple<Penalty, RequestMoreHeaders> {
    bool request_more_headers = false;

    if (find_bad_header(headers)) return {Penalty::BadBlockPenalty, request_more_headers};

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();  // todo: Erigon here pass also headerRaw

    if (penalty != Penalty::NoPenalty) return {penalty, request_more_headers};

    for (auto& segment : segments) {
        request_more_headers |= process_segment(segment, false, peer_id);
    }

    return {Penalty::NoPenalty, request_more_headers};
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
 * these properties:
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

        if (contains(dedupMap, header_hash)) {
            return {std::vector<Segment>{}, Penalty::DuplicateHeaderPenalty};
        }

        dedupMap.insert(header_hash);
        auto children = childrenMap[header_hash];
        auto [valid, penalty] = HeaderList::childrenParentValidity(children, header);
        if (!valid) {
            return {std::vector<Segment>{}, penalty};
        }

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

auto WorkingChain::process_segment(const Segment& segment, bool is_a_new_block, const PeerId& peerId)
    -> RequestMoreHeaders {
    auto [foundAnchor, start] = find_anchor(segment);
    auto [foundTip, end] = find_link(segment, start);

    if (end == 0) {
        log::Debug() << "WorkingChain: duplicated segment, bn=" << segment[start]->number << ", "
                     << (foundAnchor ? "removing corresponding anchor" : "corresponding anchor not found");
        // If duplicate segment is extending from the anchor, the anchor needs to be deleted,
        // otherwise it will keep producing requests that will be found duplicate
        if (foundAnchor) remove_anchor(segment[start]->hash());  // note: hash and not parent_hash
        return false;
    }

    auto lowest_header = segment.back();
    auto height = lowest_header->number;

    if (is_a_new_block || seen_announces_.get(Hash(lowest_header->hash())) != nullptr) {
        if (height > top_seen_height_) top_seen_height_ = height;
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
        log::Debug() << "Segment: " << op << " start=" << startNum << " end=" << endNum << " (more=" << requestMore << ")";
    } catch (segment_cut_and_paste_error& e) {
        log::Debug() << "Segment: " << op << " failure, reason:" << e.what();
        return false;
    }

    reduce_links_to(link_limit);

    // select { case hd.DeliveryNotify <- struct{}{}: default: } // todo: translate

    return requestMore /* && hd.requestChaining */;  // todo: translate requestChaining
}

void WorkingChain::reduce_links_to(size_t limit) {
    if (link_queue_.size() <= limit) return;  // does nothing

    log::Debug() << "LinkQueue: too many links, cutting down from " << link_queue_.size() << " to " << link_limit;

    while (link_queue_.size() > limit) {
        auto link = link_queue_.top();
        link_queue_.pop();
        links_.erase(link->hash);
        // delete not needed, using shared_ptr

        auto parentLink_i = links_.find(link->header->parent_hash);
        if (parentLink_i != links_.end()) parentLink_i->second->remove_child(link);

        auto anchor_i = anchors_.find(link->header->parent_hash);
        if (anchor_i != anchors_.end()) anchor_i->second->remove_child(link);
    }
}

// find_anchors tries to find the highest link the in the new segment that can be attached to an existing anchor
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
        if (preverified_hashes_->contains(link->hash)) mark_as_preverified(link);
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

    if (contains(bad_headers_, attachment_link.value()->hash)) {
        invalidate(*anchor);
        // todo: add & return penalties: []PenaltyItem := append(penalties, PenaltyItem{Penalty: AbandonedAnchorPenalty,
        // PeerID: anchor.peerID})
    } else if (attachment_link.value()->persisted) {
        auto link = links_.find(link_header->hash());
        if (link != links_.end())  // todo: Erigon code assume true always, check!
            insert_list_.push(link->second);
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
    // But removal will happen anyway, in th function RequestMoreHeaders, if it disappears from the map

    // todo: modularize this block in "add_anchor_if_not_present"
    auto new_anchor_header = *segment_slice.rbegin();  // lowest header
    std::shared_ptr<Anchor> new_anchor;
    a = anchors_.find(new_anchor_header->parent_hash);
    bool pre_existing = a != anchors_.end();
    if (!pre_existing) {
        new_anchor = std::make_shared<Anchor>(*new_anchor_header, old_anchor->peerId);
        if (new_anchor->blockHeight > 0) {
            anchors_[new_anchor_header->parent_hash] = new_anchor;
            anchor_queue_.push(new_anchor);
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
        if (preverified_hashes_->contains(link->hash)) mark_as_preverified(link);
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
        if (preverified_hashes_->contains(link->hash)) mark_as_preverified(link);
    }

    if (attachment_link.value()->persisted && !contains(bad_headers_, attachment_link.value()->hash)) {
        auto link = links_.find(link_header->hash());
        if (link != links_.end())  // todo: Erigon code assume true always, check!
            insert_list_.push(link->second);
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
        if (anchor_header->number < highest_in_db_)
            throw segment_cut_and_paste_error(
                "segment cut&paste error, new anchor too far in the past: " + to_string(anchor_header->number) +
                ", latest header in db: " + to_string(highest_in_db_));
        if (anchors_.size() >= anchor_limit)
            throw segment_cut_and_paste_error("segment cut&paste error, too many anchors: " +
                                              to_string(anchors_.size()) + ", limit: " + to_string(anchor_limit));

        anchor = std::make_shared<Anchor>(*anchor_header, peerId);
        anchors_[anchor_header->parent_hash] = anchor;
        anchor_queue_.push(anchor);
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
        if (preverified_hashes_->contains(link->hash)) mark_as_preverified(link);
    }

    return !pre_existing;
}

auto WorkingChain::add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link> {
    auto link = std::make_shared<Link>(header, persisted);
    links_[link->hash] = link;
    if (persisted)
        persisted_link_queue_.push(link);
    else
        link_queue_.push(link);

    return link;
}

void WorkingChain::remove(Anchor& anchor) { remove_anchor(anchor.parentHash); }

void WorkingChain::remove_anchor(const Hash& hash) {
    // Anchor is removed from the map, but not from the anchorQueue
    // This is because it is hard to find the index under which the anchor is stored in the anchorQueue
    // But removal will happen anyway, in the function request_more_headers, if it disappears from the map
    size_t erased = anchors_.erase(hash);
    if (erased == 0) {
        log::Warning() << "WorkingChain: removal of anchor failed, " << to_hex(hash) << " not found";
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
    preverified_hashes_ = preverifiedHashes;
}

}  // namespace silkworm
