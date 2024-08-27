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

#include "header_chain.hpp"

#include <algorithm>

#include <gsl/util>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/common/singleton.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/db_utils.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/sync/sentry_client.hpp>

#include "algorithm.hpp"

namespace silkworm {

class SegmentCutAndPasteError : public std::logic_error {
  public:
    SegmentCutAndPasteError() : std::logic_error("segment cut&paste error, unknown reason") {}

    explicit SegmentCutAndPasteError(const std::string& reason) : std::logic_error(reason) {}
};

HeaderChain::HeaderChain(const ChainConfig& chain_config)
    : HeaderChain(protocol::rule_set_factory(chain_config), chain_config.terminal_total_difficulty) {}

HeaderChain::HeaderChain(protocol::RuleSetPtr rule_set, std::optional<intx::uint256> terminal_total_difficulty)
    : highest_in_db_(0),
      top_seen_height_(0),
      preverified_hashes_(PreverifiedHashes::current),
      seen_announces_(1000),
      rule_set_{std::move(rule_set)},
      chain_state_(persisted_link_queue_),  // Erigon reads past headers from db, we hope to find them from this queue
      terminal_total_difficulty_{terminal_total_difficulty} {
    if (!rule_set_) {
        throw std::logic_error("HeaderChain exception, cause: unknown protocol rule set");
        // or must the sync go on and return StageResult::kUnknownProtocolRuleSet?
    }

    // User can specify to stop downloading process at some block
    const auto stop_at_block = Environment::get_stop_at_block();
    if (stop_at_block.has_value()) {
        set_target_block(stop_at_block.value());
        SILK_TRACE << "HeaderChain target block=" << target_block_.value();
    }

    RandomNumber random(100'000'000, 1'000'000'000);
    request_id_prefix = random.generate_one();
    SILK_TRACE << "HeaderChain: request id prefix=" << request_id_prefix;
}

void HeaderChain::set_target_block(BlockNum target_block) {
    target_block_ = target_block;
    top_seen_height_ = target_block;  // needed if no header announcements on p2p network

    compute_last_preverified_hash();
}

void HeaderChain::compute_last_preverified_hash() {
    last_preverified_hash_ = preverified_hashes_.height;
    if (target_block_ && preverified_hashes_.step)
        last_preverified_hash_ = (*target_block_ / preverified_hashes_.step) * preverified_hashes_.step;
}

BlockNum HeaderChain::highest_block_in_db() const { return highest_in_db_; }

void HeaderChain::top_seen_block_height(BlockNum n) { top_seen_height_ = n; }

BlockNum HeaderChain::top_seen_block_height() const { return top_seen_height_; }

std::pair<BlockNum, BlockNum> HeaderChain::anchor_height_range() const {
    if (anchors_.empty()) return {0, 0};
    BlockNum min{std::numeric_limits<BlockNum>::max()}, max{0};
    for (auto& a : anchors_) {
        auto& anchor = a.second;
        min = std::min(min, anchor->blockHeight);
        max = std::max(max, anchor->blockHeight);
    }
    return {min, max};
}

bool HeaderChain::in_sync() const {
    BlockNum tip_block = target_block_ ? target_block_.value() : std::max(preverified_hashes_.height, top_seen_height_);
    return top_seen_height_ > 0 && highest_in_db_ >= tip_block;
}

size_t HeaderChain::pending_links() const { return links_.size() - persisted_link_queue_.size(); }

size_t HeaderChain::anchors() const { return anchors_.size(); }

std::vector<Announce>& HeaderChain::announces_to_do() { return announces_to_do_; }

size_t HeaderChain::outstanding_requests(time_point_t tp) const {
    auto it = std::find_if(anchor_queue_.begin(), anchor_queue_.end(), [tp](const auto& anchor) {
        return anchor->timestamp > tp;  // anchor_queue_ is sorted by timestamp
    });
    auto distance = std::distance(it, anchor_queue_.end());  // skip adding (last_skeleton_request_ < tp ? 1 : 0)
                                                             // because we cannot say here if it has already been replied
    if (distance < 0) throw std::logic_error("HeaderChain::outstanding_requests() distance < 0");

    return static_cast<size_t>(distance);
}

void HeaderChain::add_bad_headers(const std::set<Hash>& bads) {
    bad_headers_.insert(bads.begin(), bads.end());  // todo: use set_union or merge?
}

void HeaderChain::initial_state(const std::vector<BlockHeader>& last_headers) {
    statistics_ = {};  // reset statistics

    // we also need here all the headers with height == highest_in_db to init chain_state_
    for (auto&& header : last_headers) {
        this->add_header_as_link(header, true);  // todo: optimize add_header_as_link to use Header&&
        highest_in_db_ = std::max(highest_in_db_, header.number);
    }

    reduce_persisted_links_to(persistent_link_limit);  // resize persisted_link_queue removing old links
}

void HeaderChain::current_state(BlockNum highest_in_db) {
    highest_in_db_ = highest_in_db;

    statistics_ = {};  // reset statistics
}

Headers HeaderChain::withdraw_stable_headers() {
    Headers stable_headers;

    if (insert_list_.empty()) return {};

    auto initial_highest_in_db = highest_in_db_;
    SILK_TRACE << "HeaderChain: finding headers to persist on top of " << highest_in_db_ << " (" << insert_list_.size()
               << " waiting in queue)";

    OldestFirstLinkQueue assessing_list = insert_list_;  // use move() operation if it is assured that after the move
    insert_list_.clear();                                // the container is empty and can be reused

    while (!assessing_list.empty()) {
        // Choose a link at top
        auto link = assessing_list.top();  // from lower block numbers to higher block numbers
        assessing_list.pop();

        // If it is in the pre-verified headers range do not verify it, wait for pre-verification
        if (link->blockHeight <= last_preverified_hash_ && !link->preverified) {
            insert_list_.push(link);
            continue;  // header should be pre-verified, but not yet, try again later
        }

        // Verify
        VerificationResult assessment = verify(*link);

        if (assessment == Postpone) {
            insert_list_.push(link);
            log::Warning() << "HeaderChain: added future link,"
                           << " hash=" << link->hash << " height=" << link->blockHeight
                           << " timestamp=" << link->header->timestamp << ")";
            continue;
        }

        if (assessment == Skip) {
            links_.erase(link->hash);
            log::Warning() << "HeaderChain: skipping link at " << link->blockHeight;
            continue;  // todo: do we need to invalidate all the descendants?
        }

        // assessment == accept

        // If we received an announcement for this header we must propagate it
        if (seen_announces_.get(link->hash)) {
            seen_announces_.remove(link->hash);
            announces_to_do_.push_back({link->hash, link->blockHeight});
        }

        // Insert in the list of headers to persist
        stable_headers.push_back(link->header);  // will be persisted by HeaderPersistence

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
            link->next.clear();
        }

        // Make sure long insertions do not appear as a stuck stage headers
        if (stable_headers.size() % 1000 == 0) {
            SILK_TRACE << "HeaderChain: " << stable_headers.size() << " headers prepared for persistence on top of "
                       << initial_highest_in_db << " (cont.)";
        }
    }

    if (!stable_headers.empty()) {
        log::Trace() << "[INFO] HeaderChain: " << stable_headers.size()
                     << " headers prepared for persistence on top of " << initial_highest_in_db << " (from "
                     << header_at(stable_headers.begin()).number << " to " << header_at(stable_headers.rbegin()).number
                     << ")";
    }

    // Save memory
    reduce_persisted_links_to(persistent_link_limit);

    return stable_headers;  // RVO
}

HeaderChain::VerificationResult HeaderChain::verify(const Link& link) {
    if (link.preverified) return Preverified;

    // todo: Erigon here searches in the db to see if the link is already present and in this case Skips it

    if (bad_headers_.contains(link.hash)) {
        return Skip;
    }

    bool with_future_timestamp_check = true;
    const auto result = rule_set_->validate_block_header(*link.header, chain_state_, with_future_timestamp_check);

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
void HeaderChain::reduce_persisted_links_to(size_t limit) {
    if (persisted_link_queue_.size() <= limit) return;

    auto initial_size = persisted_link_queue_.size();

    while (persisted_link_queue_.size() > limit) {
        auto link = persisted_link_queue_.top();
        persisted_link_queue_.pop();

        links_.erase(link->hash);
    }

    SILK_TRACE << "PersistedLinkQueue: too many links, cut down from " << initial_size << " to "
               << persisted_link_queue_.size();
}

/*
 * Add a ready header to the chain, if it becomes a new anchor then try to extend it if there are no other anchors
 */
std::shared_ptr<OutboundMessage> HeaderChain::add_header(const BlockHeader& anchor, time_point_t tp) {
    SILK_TRACE << "HeaderChain: adding header " << anchor.number << " " << Hash{anchor.hash()};

    statistics_.received_items += 1;

    auto header_list = HeaderList::make({anchor});

    auto [segments, penalty] = header_list->split_into_segments();

    if (penalty != Penalty::NoPenalty) {
        statistics_.reject_causes.invalid += 1;
        return nullptr;
    }

    SILKWORM_ASSERT(segments.size() == 1);

    auto segment = segments[0];

    if (target_block_) segment.remove_headers_higher_than(*target_block_);

    auto want_to_extend = process_segment(segment, true, no_peer);
    if (!want_to_extend) return nullptr;

    return anchor_extension_request(tp);
}

/*
 * Advance the chain requesting new headers
 */
std::shared_ptr<OutboundMessage> HeaderChain::request_headers(time_point_t tp) {
    auto skeleton_req = anchor_skeleton_request(tp);
    if (skeleton_req) return skeleton_req;

    return anchor_extension_request(tp);
}

/*
 * Skeleton query.
 * Request "seed" headers that can became anchors.
 * It requests N headers starting at highestInDb + stride up to topSeenHeight.
 * If there is an anchor at height < topSeenHeight this will be the top limit: this way we prioritize the fill of a big
 * hole near the bottom. If the lowest hole is not so big we do not need a skeleton query yet.
 */
std::shared_ptr<OutboundMessage> HeaderChain::anchor_skeleton_request(time_point_t time_point) {
    using namespace std::chrono_literals;

    // if last skeleton request was too recent, do not request another one
    if (time_point - last_skeleton_request_ < skeleton_req_interval) {
        skeleton_condition_ = "too recent";
        return nullptr;
    }

    last_skeleton_request_ = time_point;

    // BlockNum top = target_height ? std::min(top_seen_height_, *target_height) : top_seen_height_;
    BlockNum top = target_block_ ? std::min(top_seen_height_, *target_block_) : top_seen_height_;

    [[maybe_unused]] auto _ = gsl::finally([&] {
        SILK_TRACE << "HeaderChain, skeleton request, condition = " << skeleton_condition_
                   << ", anchors = " << anchors_.size()
                   << ", target = " << top
                   << ", highest_in_db = " << highest_in_db_ << ")";
    });

    if (anchors_.size() > 64) {
        skeleton_condition_ = "busy";
        return nullptr;
    }

    if (top <= highest_in_db_) {
        skeleton_condition_ = "end";
        return nullptr;
    }

    auto lowest_anchor = lowest_anchor_within_range(highest_in_db_, top + 1);
    // using bottom variable in place of highest_in_db_ in the range is wrong because if there is an anchor under
    // bottom we issue a wrong request, f.e. if the anchor=1536 was extended down we would request again origin=1536

    BlockNum next_target = top;
    if (lowest_anchor) {
        if (*lowest_anchor - highest_in_db_ <= stride) {  // the lowest_anchor is too close to highest_in_db
            skeleton_condition_ = "working";
            return nullptr;
        }
        next_target = *lowest_anchor;
    } else {                                   // there are no anchors
        if (top - highest_in_db_ <= stride) {  // the top is too close to highest_in_db
            if (target_block_) {               // we are syncing to a specific block
                skeleton_condition_ = "near the top";
                auto request_message = std::make_shared<OutboundGetBlockHeaders>();
                request_message->packet().requestId = generate_request_id();
                request_message->packet().request = {{top}, max_len, 0, true};  // request top header only
                return request_message;
            }
            skeleton_condition_ = "wait tip announce";
            return nullptr;
        }
    }

    BlockNum length = (next_target - highest_in_db_) / stride;

    if (length > max_len) length = max_len;

    if (length == 0) {
        skeleton_condition_ = "low";
        return nullptr;
    }

    auto request_message = std::make_shared<OutboundGetBlockHeaders>();
    auto& packet = request_message->packet();
    packet.requestId = generate_request_id();
    packet.request.origin = {highest_in_db_ + stride};
    packet.request.amount = length;
    packet.request.skip = length > 1 ? stride - 1 : 0;
    packet.request.reverse = false;

    statistics_.requested_items += length;
    skeleton_condition_ = "ok";

    return request_message;
}

size_t HeaderChain::anchors_within_range(BlockNum max) {
    return static_cast<size_t>(
        std::ranges::count_if(anchors_, [&max](const auto& anchor) { return anchor.second->blockHeight < max; }));
}

std::optional<BlockNum> HeaderChain::lowest_anchor_within_range(BlockNum bottom, BlockNum top) {
    BlockNum lowest = top;
    bool present = false;
    for (const auto& anchor : anchors_) {
        if (anchor.second->blockHeight >= bottom && anchor.second->blockHeight < lowest) {
            lowest = anchor.second->blockHeight;
            present = true;
        }
    }
    return present ? std::optional{lowest} : std::nullopt;
}

std::shared_ptr<Anchor> HeaderChain::highest_anchor() {
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
std::shared_ptr<OutboundMessage> HeaderChain::anchor_extension_request(time_point_t time_point) {
    using std::nullopt;
    auto prev_condition = extension_condition_;

    if (time_point - last_nack_ < SentryClient::kNoPeerDelay)
        return {};

    if (anchor_queue_.empty()) {
        extension_condition_ = "empty anchor queue";
        if (extension_condition_ != prev_condition) {
            SILK_TRACE << "HeaderChain, no more headers to request: " << extension_condition_;
        }
        return {};
    }

    auto send_penalties = std::make_shared<OutboundGetBlockHeaders>();
    while (!anchor_queue_.empty()) {
        std::shared_ptr<Anchor> anchor = anchor_queue_.top();

        if (!anchors_.contains(anchor->parentHash)) {
            anchor_queue_.pop();  // anchor disappeared (i.e. it became link as per our request) or unavailable,
            continue;             // normal condition, pop from the queue and move on
        }

        if (anchor->timestamp > time_point) {
            extension_condition_ = "no anchor ready for extension yet";
            if (extension_condition_ != prev_condition) {
                SILK_TRACE << "HeaderChain, no more headers to request: " << extension_condition_;
            }
            return send_penalties;  // anchor not ready for "extend" re-request yet, send only penalties if any
        }

        if (anchor->timeouts < 10) {
            anchor_queue_.update(anchor, [&](const auto& a) { return a->update_timestamp(time_point + extension_req_timeout); });

            auto request_message = send_penalties;
            auto& packet = request_message->packet();
            packet.requestId = generate_request_id();
            packet.request = {{anchor->blockHeight},  // requesting from origin=blockHeight-1 make debugging difficult
                              max_len,
                              0,
                              true};  // we use blockHeight in place of parentHash to get also ommers if presents

            statistics_.requested_items += max_len;

            SILK_TRACE << "HeaderChain: trying to extend anchor " << anchor->blockHeight
                       << " (chain bundle len = " << anchor->chainLength() << ", last link = " << anchor->lastLinkHeight << " )";

            extension_condition_ = "ok";
            return request_message;  // try (again) to extend this anchor
        }

        // ancestors of this anchor seem to be unavailable, invalidate and move on
        log::Warning("HeaderChain") << "invalidating anchor for suspected unavailability, "
                                    << "height=" << anchor->blockHeight;
        // no need to do anchor_queue_.pop(), implicitly done in the following
        invalidate(anchor);
        send_penalties->penalties().emplace_back(Penalty::AbandonedAnchorPenalty, anchor->peerId);
    }

    extension_condition_ = "void anchor queue";
    return send_penalties;
}

void HeaderChain::invalidate(const std::shared_ptr<Anchor>& anchor) {
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
std::optional<GetBlockHeadersPacket66> HeaderChain::save_external_announce(Hash hash) {
    if (target_block_.has_value()) return std::nullopt;  // with stop_at_block we do not use announcements

    seen_announces_.put(hash, 0);  // we ignore the value in the map (zero here), we only need the key

    if (has_link(hash)) return std::nullopt;  // we already have this link, no need to request it

    GetBlockHeadersPacket66 request;
    request.requestId = Singleton<RandomNumber>::instance().generate_one();
    request.request.origin = {hash};
    request.request.amount = 1;
    request.request.skip = 0;
    request.request.reverse = false;

    return request;
}

void HeaderChain::request_nack(const GetBlockHeadersPacket66& packet) {
    last_nack_ = std::chrono::system_clock::now();

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
        log::Trace() << "[WARNING] HeaderChain: failed restoring timestamp due to request nack, requestId="
                     << packet.requestId;
        return;  // not found
    }

    log::Trace() << "[INFO] HeaderChain: restoring timestamp due to request nack, requestId=" << packet.requestId;

    anchor_queue_.update(anchor, [&](auto& anchor_) { anchor_->restore_timestamp(); });
}

bool HeaderChain::has_link(Hash hash) { return (links_.find(hash) != links_.end()); }

bool HeaderChain::find_bad_header(const std::vector<BlockHeader>& headers) {
    return std::ranges::any_of(headers, [this](const BlockHeader& header) {
        if (is_zero(header.parent_hash) && header.number != 0) {
            log::Warning("HeaderStage") << "received malformed header: " << header.number;
            return true;
        }
        // Quick-and-dirty validity check based on header difficulty and PoS transition
        if (header.difficulty == 0 && !terminal_total_difficulty_.has_value()) {
            log::Warning("HeaderStage") << "received header w/ zero difficulty, block=" << header.number;
            return true;
        }
        Hash header_hash = header.hash();
        if (bad_headers_.contains(header_hash)) {
            log::Warning("HeaderStage") << "received bad header: " << header.number;
            return true;
        }
        return false;
    });
}

std::tuple<Penalty, HeaderChain::RequestMoreHeaders> HeaderChain::accept_headers(const std::vector<BlockHeader>& headers, uint64_t requestId, const PeerId& peer_id) {
    bool request_more_headers = false;

    if (headers.empty()) {
        statistics_.received_items += 1;
        statistics_.reject_causes.invalid++;
        return {Penalty::DuplicateHeaderPenalty, request_more_headers};  // todo: use UselessPeer message
    }

    statistics_.received_items += headers.size();

    if (headers.begin()->number < top_seen_height_ &&  // an old header announcement?
        !is_valid_request_id(requestId)) {             // anyway is not requested by us...
        statistics_.reject_causes.not_requested += headers.size();
        SILK_TRACE << "Rejecting message with reqId=" << requestId << " and first block=" << headers.begin()->number;
        return {Penalty::NoPenalty, request_more_headers};
    }

    if (find_bad_header(headers)) {
        statistics_.reject_causes.bad += headers.size();
        return {Penalty::BadBlockPenalty, request_more_headers};
    }

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments();

    if (penalty != Penalty::NoPenalty) {
        statistics_.reject_causes.invalid += headers.size();
        return {penalty, request_more_headers};
    }

    for (auto& segment : segments) {
        if (target_block_) segment.remove_headers_higher_than(*target_block_);
        request_more_headers |= process_segment(segment, false, peer_id);
    }

    return {Penalty::NoPenalty, request_more_headers};
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
std::tuple<std::vector<Segment>, Penalty> HeaderList::split_into_segments() {
    std::vector<Header_Ref> headers = to_ref();
    std::ranges::sort(headers, [](auto& h1, auto& h2) {
        return h1->number > h2->number;
    });  // sort headers from the highest block height to the lowest

    std::vector<Segment> segments;
    std::map<Hash, size_t> segmentMap;
    std::map<Hash, std::vector<Header_Ref>> childrenMap;
    std::set<Hash> dedupMap;
    size_t segmentIdx = 0;

    for (auto& header : headers) {
        Hash header_hash = header->hash();

        if (dedupMap.contains(header_hash)) {
            return {std::vector<Segment>{}, Penalty::DuplicateHeaderPenalty};
        }

        dedupMap.insert(header_hash);
        auto children = childrenMap[header_hash];
        auto [valid, penalty] = HeaderList::children_parent_validity(children, header);
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

        segmentMap[header->parent_hash] = segmentIdx;

        auto& siblings = childrenMap[header->parent_hash];
        siblings.push_back(header);
    }

    return {segments, Penalty::NoPenalty};
}

HeaderChain::RequestMoreHeaders HeaderChain::process_segment(const Segment& segment, bool is_a_new_block, const PeerId& peerId) {
    if (segment.empty()) return false;
    auto [anchor, start] = find_anchor(segment);
    auto [tip, end] = find_link(segment, start);

    if (end == 0) {
        SILK_TRACE << "HeaderChain: segment cut&paste error, duplicated segment, bn=" << segment[start]->number
                   << ", hash=" << Hash{segment[start]->hash()} << " parent-hash=" << Hash{segment[start]->parent_hash}
                   << (anchor.has_value() ? ", removing corresponding anchor" : ", corresponding anchor not found");
        // If duplicate segment is extending from the anchor, the anchor needs to be deleted,
        // otherwise it will keep producing requests that will be found duplicate
        if (anchor.has_value()) invalidate(anchor.value());
        statistics_.reject_causes.duplicated += segment.size();
        return false;
    }

    statistics_.accepted_items += end - start;
    statistics_.reject_causes.duplicated += segment.size() - (end - start);

    auto highest_header = segment.front();
    auto height = highest_header->number;
    if (height > top_seen_height_) {
        if (is_a_new_block) {
            top_seen_block_height(height);
        } else if (seen_announces_.size() != 0) {
            auto hash = highest_header->hash();
            if (seen_announces_.get(hash) != nullptr) top_seen_block_height(height);
        }
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
        // SILK_TRACE << "HeaderChain, segment " << op << " up=" << startNum << " (" << segment[start]->hash()
        //            << ") down=" << endNum << " (" << segment[end - 1]->hash() << ") (more=" << requestMore << ")";
    } catch (SegmentCutAndPasteError& e) {
        log::Trace() << "[WARNING] HeaderChain, segment cut&paste error, " << op << " up=" << startNum << " ("
                     << Hash{segment[start]->hash()} << ") down=" << endNum << " (" << Hash{segment[end - 1]->hash()}
                     << ") failed, reason: " << e.what();
        return false;
    }

    reduce_links_to(link_limit);

    return requestMore;
}

void HeaderChain::reduce_links_to(size_t limit) {
    if (pending_links() <= limit) return;  // does nothing

    auto initial_size = pending_links();

    auto victim_anchor = highest_anchor();

    invalidate(victim_anchor);

    log::Info("HeaderStage") << "LinkQueue has too many links, cut down from " << initial_size
                             << " to " << pending_links()
                             << " (removed chain bundle start=" << victim_anchor->blockHeight
                             << " end=" << victim_anchor->lastLinkHeight << ")";
}

// find_anchors tries to find the highest link the in the new segment that can be attached to an existing anchor
std::tuple<std::optional<std::shared_ptr<Anchor>>, HeaderChain::Start> HeaderChain::find_anchor(const Segment& segment) const {
    for (size_t i = 0; i < segment.size(); i++) {
        auto a = anchors_.find(segment[i]->hash());
        if (a != anchors_.end()) {  // segment[i]->hash() == anchor.parent_hash
            return {a->second, i};
        }
    }

    return {std::nullopt, 0};
}

// find_link find the highest existing link (from start) that the new segment can be attached to
std::tuple<std::optional<std::shared_ptr<Link>>, HeaderChain::End> HeaderChain::find_link(const Segment& segment, size_t start) const {
    auto duplicate_link = get_link(segment[start]->hash());
    if (duplicate_link) return {std::nullopt, 0};

    for (size_t i = start; i < segment.size(); i++) {
        // Check if the header can be attached to any links
        auto attaching_link = get_link(segment[i]->parent_hash);
        if (attaching_link) return {attaching_link, i + 1};  // return the ordinal of the next link
    }
    return {std::nullopt, segment.size()};
}

std::optional<std::shared_ptr<Link>> HeaderChain::get_link(const Hash& hash) const {
    if (auto it = links_.find(hash); it != links_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// find_anchors find the anchor the link is anchored to
std::tuple<std::optional<std::shared_ptr<Anchor>>, HeaderChain::DeepLink> HeaderChain::find_anchor(const std::shared_ptr<Link>& link) const {
    std::shared_ptr<Link> parent_link = link;
    decltype(links_.begin()) it;
    do {
        it = links_.find(parent_link->header->parent_hash);
        if (it != links_.end()) {
            parent_link = it->second;
        }
    } while (it != links_.end() && !parent_link->persisted);

    if (parent_link->persisted) {
        return {std::nullopt, parent_link};  // ok, no anchor because the link is in a segment attached to a
                                             // persisted link that we return
    }

    auto a = anchors_.find(parent_link->header->parent_hash);
    if (a == anchors_.end()) {
        log::Trace()
            << "[ERROR] HeaderChain: segment cut&paste error, segment without anchor or persisted attach point, "
            << "starting bn=" << link->blockHeight << " ending bn=" << parent_link->blockHeight << " "
            << "parent=" << to_hex(parent_link->header->parent_hash);
        return {std::nullopt, parent_link};  // wrong, invariant violation, no anchor but there should be
    }
    return {a->second, parent_link};
}

void HeaderChain::connect(const std::shared_ptr<Link>& attachment_link, Segment::Slice segment_slice,
                          const std::shared_ptr<Anchor>& anchor) {
    using std::to_string;
    // Extend up

    // Check for bad headers
    if (bad_headers_.contains(attachment_link->hash)) {
        invalidate(anchor);
        // todo: return []PenaltyItem := append(penalties, PenaltyItem{Penalty: AbandonedAnchorPenalty, PeerID:
        // anchor.peerID})
        throw SegmentCutAndPasteError(
            "anchor connected to bad headers, "
            "height=" +
            std::to_string(anchor->blockHeight) + " parent hash=" + to_hex(anchor->parentHash));
    }

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link;
    for (auto header : std::ranges::reverse_view(segment_slice)) {
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (prev_link->persisted) insert_list_.push(link);
        prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverified_hashes_.contains(link->hash)) mark_as_preverified(link);
    }

    // Update deepest anchor
    auto [deep_a, deep_link] = find_anchor(attachment_link);
    if (deep_a.has_value()) {
        auto deepest_anchor = deep_a.value();
        deepest_anchor->lastLinkHeight = std::max(deepest_anchor->lastLinkHeight, anchor->lastLinkHeight);
    } else {
        // if (!deep_link->persisted) error, else attachment to special anchor
    }

    // Extend_down

    bool anchor_preverified =
        std::ranges::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });
    prev_link->next = anchor->links;
    if (anchor_preverified) mark_as_preverified(prev_link);  // Mark the entire segment as pre-verified
    remove(anchor);

    log::Trace() << "[INFO] HeaderChain, segment op: "
                 << (deep_a.has_value()
                         ? "A " + to_string(deep_a.value()->blockHeight)
                         : "X " + to_string(deep_link->blockHeight) + (deep_link->persisted ? " (P)" : " (!P)"))
                 << " --- " << attachment_link->blockHeight << (attachment_link->preverified ? " (V)" : "")
                 << " <-connect-> " << segment_slice.rbegin()->operator*().number << " --- " << prev_link->blockHeight
                 << " <-connect-> " << anchor->blockHeight << " --- " << anchor->lastLinkHeight
                 << (anchor_preverified ? " (V)" : "");
}

HeaderChain::RequestMoreHeaders HeaderChain::extend_down(Segment::Slice segment_slice, const std::shared_ptr<Anchor>& anchor) {
    // Add or find new anchor
    auto new_anchor_header = *segment_slice.rbegin();  // lowest header
    bool check_limits = false;
    auto [new_anchor, pre_existing] = add_anchor_if_not_present(*new_anchor_header, anchor->peerId, check_limits);

    // Remove old anchor
    bool anchor_preverified =
        std::ranges::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });
    remove(anchor);

    // Iterate over headers backwards (from parents towards children)
    // Add all headers in the segments as links to this anchor
    std::shared_ptr<Link> prev_link;
    for (auto header : std::ranges::reverse_view(segment_slice)) {
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (!prev_link)
            new_anchor->links.push_back(link);  // add the link chain in the anchor
        else
            prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverified_hashes_.contains(link->hash)) mark_as_preverified(link);
    }

    new_anchor->lastLinkHeight = std::max(new_anchor->lastLinkHeight, anchor->lastLinkHeight);

    prev_link->next = anchor->links;
    if (anchor_preverified) mark_as_preverified(prev_link);  // Mark the entire segment as preverified

    bool newanchor_preverified =
        std::ranges::any_of(new_anchor->links, [](const auto& link) -> bool { return link->preverified; });

    log::Trace() << "[INFO] HeaderChain, segment op: " << new_anchor->blockHeight
                 << (newanchor_preverified ? " (V)" : "") << " --- " << prev_link->blockHeight << " <-extend down "
                 << anchor->blockHeight << " --- " << anchor->lastLinkHeight << (anchor_preverified ? " (V)" : "");

    return !pre_existing;
}

void HeaderChain::extend_up(const std::shared_ptr<Link>& attachment_link, Segment::Slice segment_slice) {
    using std::to_string;
    // Search for bad headers
    if (bad_headers_.contains(attachment_link->hash)) {
        // todo: return penalties
        throw SegmentCutAndPasteError(
            "connection to bad headers,"
            " height=" +
            std::to_string(attachment_link->blockHeight) +
            " hash=" + to_hex(attachment_link->hash));
    }

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link;
    for (auto header : std::ranges::reverse_view(segment_slice)) {
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (prev_link->persisted) insert_list_.push(link);
        prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverified_hashes_.contains(link->hash)) mark_as_preverified(link);
    }

    // Update deepest anchor
    auto [deep_a, deep_link] = find_anchor(attachment_link);
    if (deep_a.has_value()) {
        auto deepest_anchor = deep_a.value();
        deepest_anchor->lastLinkHeight = std::max(deepest_anchor->lastLinkHeight, prev_link->blockHeight);
    } else {
        // if (!deep_link->persisted) error, else attachment to special anchor
    }

    log::Trace() << "[INFO] HeaderChain, segment op: "
                 << (deep_a.has_value()
                         ? "A " + to_string(deep_a.value()->blockHeight)
                         : "X " + to_string(deep_link->blockHeight) + (deep_link->persisted ? " (P)" : " (!P)"))
                 << " --- " << attachment_link->blockHeight << (attachment_link->preverified ? " (V)" : "")
                 << " extend up-> " << segment_slice.rbegin()->operator*().number << " --- "
                 << (segment_slice.rend() - 1)->operator*().number;
}

HeaderChain::RequestMoreHeaders HeaderChain::new_anchor(Segment::Slice segment_slice, PeerId peerId) {
    using std::to_string;

    // Add or find anchor
    auto anchor_header = *segment_slice.rbegin();  // lowest header
    bool check_limits = true;
    auto [anchor, pre_existing] = add_anchor_if_not_present(*anchor_header, std::move(peerId), check_limits);

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link;
    for (auto header : std::ranges::reverse_view(segment_slice)) {
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (!prev_link)
            anchor->links.push_back(link);  // add the link chain in the anchor
        else
            prev_link->next.push_back(link);  // add link as next of the preceding
        prev_link = link;
        if (preverified_hashes_.contains(link->hash)) mark_as_preverified(link);
    }

    anchor->lastLinkHeight = std::max(anchor->lastLinkHeight, prev_link->blockHeight);

    bool anchor_preverified =
        std::ranges::any_of(anchor->links, [](const auto& link) -> bool { return link->preverified; });

    log::Trace() << "[INFO] HeaderChain, segment op: new anchor " << anchor->blockHeight << " --- "
                 << anchor->lastLinkHeight << (anchor_preverified ? " (V)" : "");

    return !pre_existing;
}

std::tuple<std::shared_ptr<Anchor>, HeaderChain::Pre_Existing> HeaderChain::add_anchor_if_not_present(const BlockHeader& anchor_header, PeerId peerId, bool check_limits) {
    using std::to_string;

    auto a = anchors_.find(anchor_header.parent_hash);
    bool pre_existing = a != anchors_.end();
    if (pre_existing) {
        return {a->second, pre_existing};
    }

    if (check_limits) {
        if (anchor_header.number < highest_in_db_)
            throw SegmentCutAndPasteError(
                "precondition not meet,"
                " new anchor too far in the past: " +
                to_string(anchor_header.number) +
                ", latest header in db: " + to_string(highest_in_db_));
        if (anchors_.size() >= anchor_limit)
            throw SegmentCutAndPasteError("too many anchors: " + to_string(anchors_.size()) +
                                          ", limit: " + to_string(anchor_limit));
    }

    std::shared_ptr<Anchor> anchor = std::make_shared<Anchor>(anchor_header, std::move(peerId));
    if (anchor->blockHeight > 0) {
        anchors_[anchor_header.parent_hash] = anchor;
        anchor_queue_.push(anchor);
    }
    return {anchor, pre_existing};
}

std::shared_ptr<Link> HeaderChain::add_header_as_link(const BlockHeader& header, bool persisted) {
    auto link = std::make_shared<Link>(header, persisted);
    links_[link->hash] = link;
    if (persisted) {
        persisted_link_queue_.push(link);
    }

    return link;
}

void HeaderChain::remove(const std::shared_ptr<Anchor>& anchor) {
    size_t erased1 = anchors_.erase(anchor->parentHash);
    bool erased2 = anchor_queue_.erase(anchor);

    if (erased1 == 0 || !erased2) {
        log::Warning("HeaderStage") << "removal of anchor failed, bn=" << anchor->blockHeight;
    }
}

// Mark a link and all its ancestors as preverified
void HeaderChain::mark_as_preverified(std::shared_ptr<Link> link) {
    while (link && !link->persisted) {
        link->preverified = true;
        auto parent = links_.find(link->header->parent_hash);
        link = (parent != links_.end() ? parent->second : nullptr);
    }
}

void HeaderChain::set_preverified_hashes(PreverifiedHashes& ph) {
    preverified_hashes_ = ph;
    compute_last_preverified_hash();
}

uint64_t HeaderChain::generate_request_id() {
    request_count++;
    if (request_count >= 10000) request_count = 0;
    return request_id_prefix * 10000 + request_count;
}

uint64_t HeaderChain::is_valid_request_id(uint64_t request_id) const {
    uint64_t prefix = request_id / 10000;
    return request_id_prefix == prefix;
}

const DownloadStatistics& HeaderChain::statistics() const { return statistics_; }

/*
std::string HeaderChain::dump_chain_bundles() const {
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
*/

}  // namespace silkworm
