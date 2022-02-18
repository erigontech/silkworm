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

    RandomNumber random(100'000'000, 1'000'000'000);
    request_id_prefix = random.generate_one();
    SILK_TRACE << "WorkingChain: request id prefix=" << request_id_prefix;
}

BlockNum WorkingChain::highest_block_in_db() const { return highest_in_db_; }

void WorkingChain::top_seen_block_height(BlockNum n) { top_seen_height_ = n; }

BlockNum WorkingChain::top_seen_block_height() const { return top_seen_height_; }

bool WorkingChain::in_sync() const {
    return highest_in_db_ >= preverified_hashes_->height && top_seen_height_ > 0 && highest_in_db_ >= top_seen_height_;
}

size_t WorkingChain::pending_links() const {
    return links_.size() - persisted_link_queue_.size();
}

size_t WorkingChain::anchors() const {
    return anchors_.size();
}

std::string WorkingChain::human_readable_status() const {
    std::string output =
           std::to_string(links_.size()) + + " links (" +
           std::to_string(pending_links()) + " pending / " +
           std::to_string(persisted_link_queue_.size()) + " persisting/ed), " +
           std::to_string(anchors_.size()) + "/" + std::to_string(anchor_queue_.size()) + " anchors, " +
           std::to_string(highest_in_db_) + " highest block in db, " +
           std::to_string(top_seen_height_) + " top seen height";

    return output;
}

std::string WorkingChain::dump_chain_bundles() const {
    // anchor list
    std::string output = "--**--\n";

    // order
    std::multimap<BlockNum, std::shared_ptr<Anchor>> ordered_anchors;
    for (auto& a : anchors_) {
        auto anchor = a.second;
        ordered_anchors.insert({anchor->blockHeight, anchor});
    }

    // dump
    for (auto& a : ordered_anchors) {
        auto anchor = a.second;
        auto seconds_from_last_req = std::chrono::duration_cast<std::chrono::seconds>(
                                                 std::chrono::system_clock::now() - anchor->timestamp);
        std::string anchor_dump = "--**-- anchor " + to_hex(anchor->parentHash) +
                                  ": start=" + std::to_string(anchor->blockHeight) +
                                  ", end=" + std::to_string(anchor->lastLinkHeight) +
                                  ", len=" + std::to_string(anchor->chainLength()) +
                                  ", ts=" + std::to_string(seconds_from_last_req.count()) + "secs\n";
        output += anchor_dump;
    }

    output += "--**--";

    return output;
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
    SILK_TRACE << "WorkingChain: finding headers to persist on top of " << highest_in_db_
                 << " (" << insert_list_.size() << " waiting in queue)";

    OldestFirstLinkQueue assessing_list = insert_list_; // use move() operation if it is assured that after the move
    insert_list_.clear();                               // the container is empty and can be reused

    while (!assessing_list.empty()) {
        // Choose a link at top
        auto link = assessing_list.top();  // from lower block numbers to higher block numbers
        assessing_list.pop();

        // If it is in the pre-verified headers range do not verify it, wait for pre-verification
        if (link->blockHeight <= preverified_hashes_->height && !link->preverified) {
            insert_list_.push(link);
            SILK_TRACE << "WorkingChain: wait for pre-verification of " << link->blockHeight;
            continue;  // header should be pre-verified, but not yet, try again later
        }

        // Verify
        VerificationResult assessment = verify(*link);

        if (assessment == Postpone) {
            insert_list_.push(link);
            log::Warning() << "WorkingChain: added future link,"
                           << " hash=" << link->hash << " height=" << link->blockHeight
                           << " timestamp=" << link->header->timestamp << ")";
            continue;
        }

        if (assessment == Skip) {
            links_.erase(link->hash);
            log::Warning() << "WorkingChain: skipping link at " << link->blockHeight;
            continue; // todo: do we need to invalidate all the descendants?
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
        persisted_link_queue_.push(link);

        // All the headers attached to this can be persisted, let's add them to the queue, this feeds the current loop
        // and cause insertion of headers in ascending order of height
        if (!link->next.empty()) {
            assessing_list.push_all(link->next);
        }

        // Make sure long insertions do not appear as a stuck stage headers
        if (stable_headers.size() % 1000 == 0) {
            SILK_TRACE << "WorkingChain: " << stable_headers.size() << " headers prepared for persistence on top of "
                        << initial_highest_in_db << " (cont.)";
        }
    }

    if (!stable_headers.empty()) {
        log::Trace() << "[INFO] WorkingChain: " << stable_headers.size() << " headers prepared for persistence on top of "
                    << initial_highest_in_db << " (from " << header_at(stable_headers.begin()).number << " to "
                    << header_at(stable_headers.rbegin()).number << ")";
    }

    // Save memory
    reduce_persisted_links_to(persistent_link_limit);

    return stable_headers;  // RVO
}

auto WorkingChain::verify(const Link& link) -> VerificationResult {
    if (link.preverified) return Preverified;

    // todo: Erigon here searches in the db to see if the link is already present and in this case Skips it

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
    if (persisted_link_queue_.size() <= limit) return;

    auto initial_size = persisted_link_queue_.size();

    while (persisted_link_queue_.size() > limit) {
        auto link = persisted_link_queue_.top();
        persisted_link_queue_.pop();

        links_.erase(link->hash);
    }

    SILK_TRACE << "PersistedLinkQueue: too many links, cut down from " << initial_size
                 << " to " << persisted_link_queue_.size();
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
    using namespace std::chrono_literals;

    if (anchors_.size() > 64) {
        statistics_.skeleton_condition = "busy";
        return std::nullopt;
    }

    BlockNum top = top_seen_height_;
    BlockNum bottom = highest_in_db_ + stride;  // warning: this can be inside a chain in memory
    if (top <= bottom) {
        statistics_.skeleton_condition = "end";
        return std::nullopt;
    }

    BlockNum lowest_anchor = lowest_anchor_within_range(highest_in_db_, top + 1);
    // using bottom variable in place of highest_in_db_ in the range is wrong because if there is an anchor under
    // bottom we issue a wrong request, f.e. if the anchor=1536 was extended down we would request again origin=1536

    if (lowest_anchor <= bottom) {
        log::Trace() << "WorkingChain, no need for skeleton request (lowest_anchor = " << lowest_anchor
                     << ", highest_in_db = " << highest_in_db_ << ")";
        statistics_.skeleton_condition = "deep";
        return std::nullopt;
    }

    BlockNum length = (lowest_anchor - bottom) / stride;

    if (length > max_len) length = max_len;

    if (length == 0) {
        log::Trace() << "WorkingChain, no need for skeleton request (lowest_anchor = " << lowest_anchor
                     << ", highest_in_db = " << highest_in_db_ << ")";
        statistics_.skeleton_condition = "low";
        return std::nullopt;
    }

    GetBlockHeadersPacket66 packet;
    packet.requestId = generate_request_id(); //RANDOM_NUMBER.generate_one();
    packet.request.origin = bottom;
    packet.request.amount = length;
    packet.request.skip = stride - 1;
    packet.request.reverse = false;

    statistics_.requested_headers += length;
    statistics_.skeleton_condition = "ok";

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

std::shared_ptr<Anchor> WorkingChain::highest_anchor() {
    std::shared_ptr<Anchor> highest_anchor = nullptr;
    for (const auto& a : anchors_) {
        if (highest_anchor == nullptr || a.second->blockHeight >= highest_anchor->blockHeight) {
            highest_anchor = a.second;
        }
    }
    return highest_anchor;
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
        log::Trace() << "[INFO] WorkingChain, no more headers to request: empty anchor queue";
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
            SILK_TRACE << "WorkingChain: no anchor ready for extension yet";
            return {nullopt, penalties};  // anchor not ready for "extend" re-request yet
        }

        if (anchor->timeouts < 10) {
            anchor->update_timestamp(time_point + timeout);
            anchor_queue_.fix();  // re-sort

            GetBlockHeadersPacket66 packet{
                generate_request_id(), //RANDOM_NUMBER.generate_one(),
                    {anchor->blockHeight, max_len, 0, true}
            }; // we use blockHeight in place of parentHash to get also ommers if presents
            // we could request from origin=blockHeight-1 but debugging becomes more difficult

            statistics_.requested_headers += max_len;

            SILK_TRACE << "WorkingChain: trying to extend anchor " << anchor->blockHeight
                         << " (chain bundle len = " << anchor->chainLength()
                         << ", last link = " << anchor->lastLinkHeight << " )";

            return {std::move(packet), std::move(penalties)};  // try (again) to extend this anchor
        } else {
            // ancestors of this anchor seem to be unavailable, invalidate and move on
            log::Warning() << "WorkingChain: invalidating anchor for suspected unavailability, "
                           << "height=" << anchor->blockHeight;
            // no need to do anchor_queue_.pop(), implicitly done in the following
            invalidate(anchor);
            penalties.emplace_back(Penalty::AbandonedAnchorPenalty, anchor->peerId);
        }
    }

    return {nullopt, penalties};
}

void WorkingChain::invalidate(std::shared_ptr<Anchor> anchor) {
    remove(anchor);
    // remove upwards
    auto& link_to_remove = anchor->links;
    while (!link_to_remove.empty()) {
        auto removal = link_to_remove.back();
        link_to_remove.pop_back();
        links_.erase(removal->hash);
        move_at_end(link_to_remove, removal->next);
    }
}

// SaveExternalAnnounce - does mark hash as seen in external announcement, only such hashes will broadcast further after
void WorkingChain::save_external_announce(Hash h) {
    seen_announces_.put(h, 0);  // we ignore the value in the map (zero here), we only need the key
}

void WorkingChain::request_nack(const GetBlockHeadersPacket66& packet) {
    std::shared_ptr<Anchor> anchor;

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

    if (anchor == nullptr) {
        log::Trace() << "[WARNING] WorkingChain: failed restoring timestamp due to request nack, requestId=" << packet.requestId;
        return;  // not found
    }

    log::Trace() << "[INFO] WorkingChain: restoring timestamp due to request nack, requestId=" << packet.requestId;

    anchor->restore_timestamp();
    anchor_queue_.fix();
}

bool WorkingChain::has_link(Hash hash) { return (links_.find(hash) != links_.end()); }

auto WorkingChain::find_bad_header(const std::vector<BlockHeader>& headers) -> bool {
    for (auto& header : headers) {
        if (is_zero(header.parent_hash) && header.number != 0) {
            log::Warning() << "WorkingChain: received malformed header: " << header.number;
            return true;
        }
        if (header.difficulty == 0) {
            log::Warning() << "WorkingChain: received header w/ wrong diff: " << header.number;
            return true;
        }
        Hash header_hash = header.hash();
        if (contains(bad_headers_, header_hash)) {
            log::Warning() << "WorkingChain: received bad header: " << header.number;
            return true;
        }
    }
    return false;
}

auto WorkingChain::accept_headers(const std::vector<BlockHeader>& headers, uint64_t requestId, const PeerId& peer_id)
    -> std::tuple<Penalty, RequestMoreHeaders> {
    bool request_more_headers = false;

    if (headers.empty()) return {Penalty::NoPenalty, request_more_headers};
    statistics_.received_headers += headers.size();

    if (headers.begin()->number < top_seen_height_ &&  // an old header announcement? .
        !is_valid_request_id(requestId)) {   // anyway is not requested by us..
        statistics_.not_requested_headers += headers.size();
        SILK_TRACE << "Rejecting message with reqId=" << requestId << " and first block=" << headers.begin()->number;
        return {Penalty::NoPenalty, request_more_headers};
    }

    if (find_bad_header(headers)) {
        statistics_.bad_headers += headers.size();
        return {Penalty::BadBlockPenalty, request_more_headers};
    }

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    if (penalty != Penalty::NoPenalty) {
        statistics_.invalid_headers += headers.size();
        return {penalty, request_more_headers};
    }

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
    auto [anchor, start] = find_anchor(segment);
    auto [tip, end] = find_link(segment, start);

    if (end == 0) {
        SILK_TRACE << "WorkingChain: segment cut&paste error, duplicated segment, bn=" << segment[start]->number
                     << ", hash=" << segment[start]->hash() << " parent-hash=" << segment[start]->parent_hash
                     << (anchor.has_value() ? ", removing corresponding anchor" : ", corresponding anchor not found");
        // If duplicate segment is extending from the anchor, the anchor needs to be deleted,
        // otherwise it will keep producing requests that will be found duplicate
        if (anchor.has_value()) invalidate(anchor.value());
        statistics_.duplicated_headers += segment.size();
        return false;
    }

    statistics_.accepted_headers += end - start;
    statistics_.duplicated_headers += segment.size() - (end - start);

    auto highest_header = segment.front();
    auto height = highest_header->number;
    if (height > top_seen_height_ &&
        (is_a_new_block || seen_announces_.get(Hash(highest_header->hash())) != nullptr)) {
        top_seen_height_ = height;
    }

    auto startNum = segment[start]->number;
    auto endNum = segment[end - 1]->number;

    Segment::Slice segment_slice = segment.slice(start, end);

    std::string op;
    bool requestMore = false;
    try {
        if (anchor.has_value()) {
            if (tip.has_value()) {
                op = "connect";
                connect(*tip, segment_slice, *anchor);
            } else {
                op = "extend down";
                requestMore = extend_down(segment_slice, *anchor);
            }
        } else if (tip.has_value()) {
            if (end > 0) {
                op = "extend up";
                extend_up(*tip, segment_slice);
            }
        } else {
            op = "new anchor";
            requestMore = new_anchor(segment_slice, peerId);
        }
        SILK_TRACE << "WorkingChain, segment " << op << " up=" << startNum << " (" << segment[start]->hash()
                    << ") down=" << endNum << " (" << segment[end - 1]->hash() << ") (more=" << requestMore << ")";
    } catch (segment_cut_and_paste_error& e) {
        log::Trace() << "[WARNING] WorkingChain, segment cut&paste error, " << op << " up=" << startNum << " ("
                       << segment[start]->hash() << ") down=" << endNum << " (" << segment[end - 1]->hash()
                       << ") failed, reason: " << e.what();
        return false;
    }

    reduce_links_to(link_limit);

    return requestMore /* && hd.requestChaining */;  // todo: implement requestChaining
}

void WorkingChain::reduce_links_to(size_t limit) {
    if (pending_links() <= limit) return;  // does nothing

    auto initial_size = pending_links();

    auto victim_anchor = highest_anchor();

    invalidate(victim_anchor);

    log::Info() << "LinkQueue: too many links, cut down from " << initial_size << " to " << pending_links()
                 << " (removed chain bundle start=" << victim_anchor->blockHeight
                 << " end=" << victim_anchor->lastLinkHeight << ")";
}

// find_anchors tries to find the highest link the in the new segment that can be attached to an existing anchor
auto WorkingChain::find_anchor(const Segment& segment) const
    -> std::tuple<std::optional<std::shared_ptr<Anchor>>, Start> {
    for (size_t i = 0; i < segment.size(); i++) {
        auto a = anchors_.find(segment[i]->hash());  // todo: hash() compute the value, save cpu
        if (a != anchors_.end()) {                   // segment[i]->hash() == anchor.parent_hash
            return {a->second, i};
        }
    }

    return {std::nullopt, 0};
}

// find_link find the highest existing link (from start) that the new segment can be attached to
auto WorkingChain::find_link(const Segment& segment, size_t start) const
    -> std::tuple<std::optional<std::shared_ptr<Link>>, End> {
    auto duplicate_link = get_link(segment[start]->hash());
    if (duplicate_link) return {std::nullopt, 0};

    for (size_t i = start; i < segment.size(); i++) {
        // Check if the header can be attached to any links
        auto attaching_link = get_link(segment[i]->parent_hash);
        if (attaching_link) return {attaching_link, i + 1};  // return the ordinal of the next link
    }
    return {std::nullopt, segment.size()};
}

auto WorkingChain::get_link(const Hash& hash) const -> std::optional<std::shared_ptr<Link>> {
    if (auto it = links_.find(hash); it != links_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// find_anchors find the anchor the link is anchored to
auto WorkingChain::find_anchor(std::shared_ptr<Link> link) const
    -> std::tuple<std::optional<std::shared_ptr<Anchor>>, DeepLink> {
    auto parent_link = link;
    decltype(links_.begin()) it;
    do {
        it = links_.find(parent_link->header->parent_hash);
        if (it != links_.end()) {
            parent_link = it->second;
        }
    } while (it != links_.end() && !parent_link->persisted);

    if (parent_link->persisted) {
        return {std::nullopt, parent_link};  // ok, no anchor because the link is in a segment attached to a
    }                                                // persisted link that we return

    auto a = anchors_.find(parent_link->header->parent_hash);
    if (a == anchors_.end()) {
        log::Trace() << "[ERROR] WorkingChain: segment cut&paste error, segment without anchor or persisted attach point, "
                     << "starting bn=" << link->blockHeight << " ending bn=" << parent_link->blockHeight << " "
                     << "parent=" << to_hex(parent_link->header->parent_hash);
        return {std::nullopt, parent_link};  // wrong, invariant violation, no anchor but there should be
    }
    return {a->second, parent_link};
}

void WorkingChain::connect(std::shared_ptr<Link> attachment_link, Segment::Slice segment_slice,
                           std::shared_ptr<Anchor> anchor) {
    using std::to_string;
    // Extend up

    // Check for bad headers
    if (contains(bad_headers_, attachment_link->hash)) {
        invalidate(anchor);
        // todo: return []PenaltyItem := append(penalties, PenaltyItem{Penalty: AbandonedAnchorPenalty, PeerID:
        // anchor.peerID})
        throw segment_cut_and_paste_error("anchor connected to bad headers, "
            "height=" + std::to_string(anchor->blockHeight) + " parent hash=" + to_hex(anchor->parentHash));
    }

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link;
    for (auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (prev_link->persisted) insert_list_.push(link);
        prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverified_hashes_->contains(link->hash)) mark_as_preverified(link);
    }

    // Update deepest anchor
    auto [deep_a, deep_link] = find_anchor(attachment_link);
    if (deep_a.has_value()) {
        auto deepest_anchor = deep_a.value();
        deepest_anchor->lastLinkHeight = std::max(deepest_anchor->lastLinkHeight, anchor->lastLinkHeight);
    }
    else {
        // if (!deep_link->persisted) error, else attachment to special anchor
    }

    // Extend_down

    bool anchor_preverified =
        as_range::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });
    prev_link->next = anchor->links;
    if (anchor_preverified) mark_as_preverified(prev_link);  // Mark the entire segment as pre-verified
    remove(anchor);

    log::Trace() << "[INFO] WorkingChain, segment op: "
        << (deep_a.has_value() ?
                            "A " + to_string(deep_a.value()->blockHeight) :
                            "X " + to_string(deep_link->blockHeight) + (deep_link->persisted ? " (P)" : " (!P)"))
        << " --- " << attachment_link->blockHeight << (attachment_link->preverified ? " (V)": "" )
        << " <-connect-> "
        << segment_slice.rbegin()->operator*().number << " --- " << prev_link->blockHeight
        << " <-connect-> "
        << anchor->blockHeight << " --- " <<  anchor->lastLinkHeight << (anchor_preverified ? " (V)" : "");
}

auto WorkingChain::extend_down(Segment::Slice segment_slice, std::shared_ptr<Anchor> anchor) -> RequestMoreHeaders {
    // Add or find new anchor
    auto new_anchor_header = *segment_slice.rbegin();  // lowest header
    bool check_limits = false;
    auto [new_anchor, pre_existing] =
        add_anchor_if_not_present(*new_anchor_header, anchor->peerId, check_limits);

    // Remove old anchor
    bool anchor_preverified =
        as_range::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });
    remove(anchor);

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

    new_anchor->lastLinkHeight = std::max(new_anchor->lastLinkHeight, anchor->lastLinkHeight);

    prev_link->next = anchor->links;
    if (anchor_preverified) mark_as_preverified(prev_link);  // Mark the entire segment as preverified

    bool newanchor_preverified =
        as_range::any_of(new_anchor->links, [](const auto& link) -> bool { return link->preverified; });

    log::Trace() << "[INFO] WorkingChain, segment op: "
        << new_anchor->blockHeight << (newanchor_preverified ? " (V)" : "") << " --- " << prev_link->blockHeight
        << " <-extend down "
        << anchor->blockHeight << " --- " <<  anchor->lastLinkHeight << (anchor_preverified ? " (V)" : "");

    return !pre_existing;
}

void WorkingChain::extend_up(std::shared_ptr<Link> attachment_link, Segment::Slice segment_slice) {
    using std::to_string;
    // Search for bad headers
    if (contains(bad_headers_, attachment_link->hash)) {
        // todo: return penalties
        throw segment_cut_and_paste_error("connection to bad headers,"
            " height=" + std::to_string(attachment_link->blockHeight) +
            " hash=" + to_hex(attachment_link->hash));
    }

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link;
    for (auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (prev_link->persisted) insert_list_.push(link);
        prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverified_hashes_->contains(link->hash)) mark_as_preverified(link);
    }

    // Update deepest anchor
    auto [deep_a, deep_link] = find_anchor(attachment_link);
    if (deep_a.has_value()) {
        auto deepest_anchor = deep_a.value();
        deepest_anchor->lastLinkHeight = std::max(deepest_anchor->lastLinkHeight, prev_link->blockHeight);
    }
    else {
        // if (!deep_link->persisted) error, else attachment to special anchor
    }

    log::Trace() << "[INFO] WorkingChain, segment op: "
        << (deep_a.has_value() ?
                            "A " + to_string(deep_a.value()->blockHeight) :
                            "X " + to_string(deep_link->blockHeight) + (deep_link->persisted ? " (P)" : " (!P)"))
        << " --- " << attachment_link->blockHeight << (attachment_link->preverified ? " (V)": "" )
        << " extend up-> "
        << segment_slice.rbegin()->operator*().number << " --- " << (segment_slice.rend()-1)->operator*().number;
}

auto WorkingChain::new_anchor(Segment::Slice segment_slice, PeerId peerId) -> RequestMoreHeaders {
    using std::to_string;

    // Add or find anchor
    auto anchor_header = *segment_slice.rbegin();  // lowest header
    bool check_limits = true;
    auto [anchor, pre_existing] =
        add_anchor_if_not_present(*anchor_header, peerId, check_limits);

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

    anchor->lastLinkHeight = std::max(anchor->lastLinkHeight, prev_link->blockHeight);

    bool anchor_preverified =
        as_range::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });

    log::Trace() << "[INFO] WorkingChain, segment op: new anchor "
        << anchor->blockHeight << " --- " << anchor->lastLinkHeight << (anchor_preverified ? " (V)" : "");

    return !pre_existing;
}

auto WorkingChain::add_anchor_if_not_present(const BlockHeader& anchor_header, PeerId peerId, bool check_limits)
    -> std::tuple<std::shared_ptr<Anchor>, Pre_Existing> {
    using std::to_string;

    auto a = anchors_.find(anchor_header.parent_hash);
    bool pre_existing = a != anchors_.end();
    if (pre_existing)
        return {a->second, pre_existing};

    if (check_limits) {
        if (anchor_header.number < highest_in_db_)
            throw segment_cut_and_paste_error("precondition not meet,"
                " new anchor too far in the past: " + to_string(anchor_header.number) +
                ", latest header in db: " + to_string(highest_in_db_));
        if (anchors_.size() >= anchor_limit)
            throw segment_cut_and_paste_error("too many anchors: " + to_string(anchors_.size()) +
                ", limit: " + to_string(anchor_limit));
    }

    std::shared_ptr<Anchor> anchor = std::make_shared<Anchor>(anchor_header, peerId);
    if (anchor->blockHeight > 0) {
        anchors_[anchor_header.parent_hash] = anchor;
        anchor_queue_.push(anchor);
    }
    return {anchor, pre_existing};
}

auto WorkingChain::add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link> {
    auto link = std::make_shared<Link>(header, persisted);
    links_[link->hash] = link;
    if (persisted)
        persisted_link_queue_.push(link);

    return link;
}

void WorkingChain::remove(std::shared_ptr<Anchor> anchor) {
    size_t erased1 = anchors_.erase(anchor->parentHash);
    bool erased2 = anchor_queue_.erase(anchor);

    if (erased1 == 0 || !erased2) {
        log::Warning() << "WorkingChain: removal of anchor failed, bn=" << anchor->blockHeight;
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

uint64_t WorkingChain::generate_request_id() {
    request_count++;
    if (request_count >= 10000) request_count = 0;
    return request_id_prefix * 10000 + request_count;
}

uint64_t WorkingChain::is_valid_request_id(uint64_t request_id) {
    uint64_t prefix = request_id / 10000;
    return request_id_prefix == prefix;
}

std::ostream& operator<<(std::ostream& os, const WorkingChain::Statistics& stats) {
    uint64_t rejected_headers = stats.received_headers - stats.accepted_headers;
    uint64_t unknown = rejected_headers - stats.not_requested_headers - stats.duplicated_headers - stats.invalid_headers - stats.bad_headers;
    long perc_received = stats.requested_headers > 0 ? lround(stats.received_headers * 100.0 / stats.requested_headers) : 0;
    long perc_accepted = stats.received_headers > 0 ? lround(stats.accepted_headers * 100.0 / stats.received_headers) : 0;
    long perc_rejected = stats.received_headers > 0 ? lround(rejected_headers * 100.0 / stats.received_headers) : 0;
    os << "headers: "
       << "req=" << stats.requested_headers << " "
       << "rec=" << stats.received_headers << " (" << perc_received << "%) -> "
       << "acc=" << stats.accepted_headers << " (" << perc_accepted << "%) "
       << "rej=" << rejected_headers << " (" << perc_rejected << "%); "
       << "reject reasons: "
       << "not-req=" << stats.not_requested_headers << ", "
       << "dup=" << stats.duplicated_headers << ", "
       << "inv=" << stats.invalid_headers << ", "
       << "bad=" << stats.bad_headers << ", "
       << "unk=" << unknown;

    return os;
}

}  // namespace silkworm
