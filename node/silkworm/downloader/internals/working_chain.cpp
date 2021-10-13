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

#include <functional>

#include <silkworm/common/log.hpp>

#include "cpp20_backport.hpp"
#include "random_number.hpp"

namespace silkworm {


class segment_cut_and_paste_error: public std::logic_error {
  public:
    segment_cut_and_paste_error() : std::logic_error("segment cut&paste error, unknown reason") {}
    segment_cut_and_paste_error(const std::string& reason) : std::logic_error(reason) {}
};


WorkingChain::WorkingChain(): highestInDb_(0), topSeenHeight_(0), seenAnnounces_(1000) {
}

BlockNum WorkingChain::highest_block_in_db() const {
    return highestInDb_;
}

void WorkingChain::top_seen_block_height(BlockNum n) {
    topSeenHeight_ = n;
}

BlockNum WorkingChain::top_seen_block_height() const {
    return topSeenHeight_;
}

bool WorkingChain::in_sync() const {
    return highestInDb_ >= preverifiedHeight_ &&
           topSeenHeight_ > 0 &&
           highestInDb_ >= topSeenHeight_;
}

std::string WorkingChain::human_readable_status() const {
    return std::to_string(anchors_.size()) + " anchors, " + std::to_string(links_.size()) + " links";
}

std::vector<Announce>& WorkingChain::announces_to_do() {
    return announcesToDo_;
}

void WorkingChain::add_bad_headers(std::set<Hash> bads) {
    badHeaders_.insert(bads.begin(), bads.end());   // todo: use set_union or merge?
}

/*
func (hd *HeaderDownload) RecoverFromDb(db ethdb.RoKV) error {
	hd.lock.Lock()
	defer hd.lock.Unlock()
	// Drain persistedLinksQueue and remove links
	for hd.persistedLinkQueue.Len() > 0 {
		link := heap.Pop(hd.persistedLinkQueue).(*Link)
		delete(hd.links, link.hash)
	}
	err := db.View(context.Background(), func(tx ethdb.Tx) error {
		c, err := tx.Cursor(dbutils.HeadersBucket)
		if err != nil {
			return err
		}
		// Take hd.persistedLinkLimit headers (with the highest heights) as links
		for k, v, err := c.Last(); k != nil && hd.persistedLinkQueue.Len() < hd.persistedLinkLimit; k, v, err = c.Prev() {
			if err != nil {
				return err
			}
			var h types.Header
			if err = rlp.DecodeBytes(v, &h); err != nil {
				return err
			}
			hd.addHeaderAsLink(&h, true) // true = persisted
		}
		hd.highestInDb, err = stages.GetStageProgress(tx, stages.Headers)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
*/
void WorkingChain::recover_initial_state(Db::ReadOnlyAccess::Tx& tx) {
    reduce_persisted_links_to(0);    // drain persistedLinksQueue and remove links

    tx.read_headers_in_reverse_order(persistent_link_limit, [this](BlockHeader&& header){
        this->add_header_as_link(header, true); // todo: optimize add_header_as_link to use Header&&
    });

    //highestInDb_ = tx.read_stage_progress(db::stages::kHeadersKey); // will be done by sync_with
}

void WorkingChain::sync_current_state(BlockNum highest_in_db) {
    highestInDb_ = highest_in_db;
}

/*
/ InsertHeaders attempts to insert headers into the database, verifying them first
// It returns true in the first return value if the system is "in sync"
func (hd *HeaderDownload) InsertHeaders(hf func(header *types.Header, blockHeight uint64) error, logPrefix string, logChannel <-chan time.Time) (bool, error) {
	hd.lock.Lock()
	defer hd.lock.Unlock()
	var linksInFuture []*Link // Here we accumulate links that fail validation as "in the future"
	for len(hd.insertList) > 0 {
		// Make sure long insertions do not appear as a stuck stage 1
		select {
		case <-logChannel:
			log.Info(fmt.Sprintf("[%s] Inserting headers", logPrefix), "progress", hd.highestInDb)
		default:
		}
		link := hd.insertList[len(hd.insertList)-1]
		if link.blockHeight <= hd.preverifiedHeight && !link.preverified {
			// Header should be preverified, but not yet, try again later
			break
		}
		hd.insertList = hd.insertList[:len(hd.insertList)-1]
		skip := false
		if !link.preverified {
			if _, bad := hd.badHeaders[link.hash]; bad {
				skip = true
			} else if err := hd.engine.VerifyHeader(hd.headerReader, link.header, true); err != nil {  // true = seal
				log.Warn("Verification failed for header", "hash", link.header.Hash(), "height", link.blockHeight, "error", err)
				if errors.Is(err, consensus.ErrFutureBlock) {
					// This may become valid later
					linksInFuture = append(linksInFuture, link)
					log.Warn("Added future link", "hash", link.header.Hash(), "height", link.blockHeight, "timestamp", link.header.Time)
					continue // prevent removal of the link from the hd.linkQueue
				} else {
					skip = true
				}
			} else {
				if hd.seenAnnounces.Pop(link.hash) {
					hd.toAnnounce = append(hd.toAnnounce, Announce{Hash: link.hash, Number: link.blockHeight})
				}
			}
		}
		if _, ok := hd.links[link.hash]; ok {
			heap.Remove(hd.linkQueue, link.idx)
		}
		if skip {
			delete(hd.links, link.hash)
			continue
		}
		if err := hf(link.header, link.blockHeight); err != nil {
			return false, err
		}
		if link.blockHeight > hd.highestInDb {
			hd.highestInDb = link.blockHeight
		}
		link.persisted = true
		link.header = nil // Drop header reference to free memory, as we won't need it anymore
		heap.Push(hd.persistedLinkQueue, link)
		if len(link.next) > 0 {
			hd.insertList = append(hd.insertList, link.next...)
		}
	}
	for hd.persistedLinkQueue.Len() > hd.persistedLinkLimit {
		link := heap.Pop(hd.persistedLinkQueue).(*Link)
		delete(hd.links, link.hash)
	}
	if len(linksInFuture) > 0 {
		hd.insertList = append(hd.insertList, linksInFuture...)
		linksInFuture = nil //nolint
	}
	return hd.highestInDb >= hd.preverifiedHeight && hd.topSeenHeight > 0 && hd.highestInDb >= hd.topSeenHeight, nil
}
*/

Headers WorkingChain::withdraw_stable_headers() {
    Headers stable_headers;

    LinkList links_in_future; // here we accumulate links that fail validation as "in the future"

    while(!insertList_.empty()) {   // todo: insertList_ is a stack so we iterate it in reverse insertion order, is it correct?
        // Make sure long insertions do not appear as a stuck stage headers
        SILKWORM_LOG(LogLevel::Info) << "WorkingChain: inserting headers (" << highestInDb_ << ")\n";

        // Choose a link at top
        auto link = insertList_.top(); // is the last added
        if (link->blockHeight <= preverifiedHeight_ && !link->preverified) {
            break; // header should be preverified, but not yet, try again later
        }

        insertList_.pop();

        bool skip = false;
        if (!link->preverified) {
            if (contains(badHeaders_,link->hash))
                skip = true;
            else if (auto error = ConsensusProto::verify(*link->header); error != ConsensusProto::ERROR) {  // true = seal
                if (error == ConsensusProto::FUTURE_BLOCK) {
                    links_in_future.push_back(link);
                    SILKWORM_LOG(LogLevel::Warn) << "WorkingChain: added future link,"
                                                 << " hash=" << link->hash
                                                 << " height=" << link->blockHeight
                                                 << " timestamp=" << link->header->timestamp << ")\n";
                    continue;
                }
                else {
                    skip = true;
                }
            }
            else {
                if (seenAnnounces_.get(link->hash)) {
                    seenAnnounces_.remove(link->hash);
                    announcesToDo_.push_back({link->hash, link->blockHeight}); // todo: we do an already seen announce; is it correct?
                }
            }
        }
        if (contains(links_, link->hash)) {
            linkQueue_.erase(link);
        }
        if (skip) {
            links_.erase(link->hash);
        }

        //persisted_chain.persist_header(*link->header, link->blockHeight);
        stable_headers.push_back(link->header);

        link->persisted = true;
        link->header = nullptr; // drop header reference to free memory, as we won't need it anymore
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

    //return highestInDb_ >= preverifiedHeight_ &&
    //       topSeenHeight_ > 0 &&
    //       highestInDb_ >= topSeenHeight_;
    return stable_headers;  // RVO
}

// reduce persistedLinksQueue and remove links
void WorkingChain::reduce_persisted_links_to(size_t limit) {
    while(persistedLinkQueue_.size() > limit) {
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
    if (anchors_.size() > 16) return std::nullopt;

    if (topSeenHeight_ < highestInDb_ + stride) return std::nullopt;

    BlockNum length = (topSeenHeight_ - highestInDb_) / stride;
    if (length > max_len)
        length = max_len;

    GetBlockHeadersPacket66 packet;
    packet.requestId = RANDOM_NUMBER.generate_one();
    packet.request.origin = highestInDb_ + stride;
    packet.request.amount = length;
    packet.request.skip = stride;
    packet.request.reverse = false;

    return {packet};
}

/*
 func (hd *HeaderDownload) RequestMoreHeaders(currentTime uint64) (*HeaderRequest, []PenaltyItem) {
	hd.lock.Lock()
	defer hd.lock.Unlock()
	var penalties []PenaltyItem
	if hd.anchorQueue.Len() == 0 {
		log.Debug("Empty anchor queue")
		return nil, penalties
	}
	for hd.anchorQueue.Len() > 0 {
		anchor := (*hd.anchorQueue)[0]
		if _, ok := hd.anchors[anchor.parentHash]; ok {
			if anchor.timestamp > currentTime {
				// Anchor not ready for re-request yet
				return nil, penalties
			}
			if anchor.timeouts < 10 {
				return &HeaderRequest{Hash: anchor.parentHash, Number: anchor.blockHeight - 1, Length: 192, Skip: 0, Reverse: true}, penalties
			} else {
				// Ancestors of this anchor seem to be unavailable, invalidate and move on
				hd.invalidateAnchor(anchor)
				penalties = append(penalties, PenaltyItem{Penalty: AbandonedAnchorPenalty, PeerID: anchor.peerID})
			}
		}
		// Anchor disappeared or unavailable, pop from the queue and move on
		heap.Remove(hd.anchorQueue, 0)
	}
	return nil, penalties
}
 */


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
std::tuple<std::optional<GetBlockHeadersPacket66>,
           std::vector<PeerPenalization>> WorkingChain::request_more_headers(time_point_t time_point, seconds_t timeout) {
    using std::nullopt;

    if (anchorQueue_.empty()) {
        SILKWORM_LOG(LogLevel::Debug) << "WorkingChain, no more headers to request: empty anchor queue\n";
        return {};
    }

    std::vector<PeerPenalization> penalties;
    while (!anchorQueue_.empty()) {
        auto anchor = anchorQueue_.top();

        if (!contains(anchors_, anchor->parentHash)) {
            anchorQueue_.pop(); // anchor disappeared (i.e. it became link as per our request) or unavailable,
            continue;           // normal condition, pop from the queue and move on
        }

        if (anchor->timestamp > time_point) {
            return {nullopt, penalties}; // anchor not ready for "extend" re-request yet
        }

        if (anchor->timeouts < 10) {
            anchor->update_timestamp(time_point + timeout);
            anchorQueue_.fix();

            GetBlockHeadersPacket66 packet{RANDOM_NUMBER.generate_one(),
                                           {anchor->blockHeight, max_len, 0, true}}; // todo: why we use blockHeight in place of parentHash?
            return {packet, penalties}; // try (again) to extend this anchor
        }
        else {
            // ancestors of this anchor seem to be unavailable, invalidate and move on
            SILKWORM_LOG(LogLevel::Warn) << "WorkingChain: invalidating anchor for suspected unavailability, "
                                                << "height=" << anchor->blockHeight << "\n";
            invalidate(*anchor);
            anchors_.erase(anchor->parentHash);
            anchorQueue_.pop();
            penalties.emplace_back(Penalty::AbandonedAnchorPenalty, anchor->peerId);
        }
    }

    return {nullopt, penalties};
}

/*
func (hd *HeaderDownload) invalidateAnchor(anchor *Anchor) {
	log.Warn("Invalidating anchor for suspected unavailability", "height", anchor.blockHeight)
	delete(hd.anchors, anchor.parentHash)
	hd.removeUpwards(anchor.links)
}

func (hd *HeaderDownload) removeUpwards(toRemove []*Link) {
	for len(toRemove) > 0 {
		removal := toRemove[len(toRemove)-1]
		toRemove = toRemove[:len(toRemove)-1]
		delete(hd.links, removal.header.Hash())
		heap.Remove(hd.linkQueue, removal.idx)
		toRemove = append(toRemove, removal.next...)
	}
}
*/
void WorkingChain::invalidate(Anchor& anchor) {
    auto link_to_remove = anchor.links;
    while (!link_to_remove.empty()) {
        auto removal = link_to_remove.back();
        link_to_remove.pop_back();
        links_.erase(removal->hash);
        linkQueue_.erase(removal);
        move_at_end(link_to_remove, removal->next); // link_to_remove.insert(link_to_remove.end(),std::make_move_iterator(removal->next.begin()),std::make_move_iterator(removal->next.end())
    }
}

// SaveExternalAnnounce - does mark hash as seen in external announcement, only such hashes will broadcast further after
void WorkingChain::save_external_announce(Hash h) {
    seenAnnounces_.put(h, 0);   // we ignore the value in the map (zero here), we only need the key
}

/*
func (hd *HeaderDownload) SentRequest(req *HeaderRequest, currentTime, timeout uint64) {
    hd.lock.Lock()
        defer hd.lock.Unlock()
            anchor, ok := hd.anchors[req.Hash]
               if !ok {
                   return
               }
               anchor.timeouts++
               anchor.timestamp = currentTime + timeout
               heap.Fix(hd.anchorQueue, 0)
}
*/

void WorkingChain::request_nack(const GetBlockHeadersPacket66& packet) {
    std::shared_ptr<Anchor> anchor;

    SILKWORM_LOG(LogLevel::Warn) << "WorkingChain: restoring some timestamp due to request nack\n";

    if (std::holds_alternative<Hash>(packet.request.origin)) {
        Hash hash = std::get<Hash>(packet.request.origin);
        auto anchor_it = anchors_.find(hash);
        if (anchor_it != anchors_.end())
            anchor = anchor_it->second;
    }
    else {
        BlockNum bn = std::get<BlockNum>(packet.request.origin);
        for(const auto& p: anchors_) {
            if (p.second->blockHeight == bn) {  // this search it is burdensome but should rarely occur
                anchor = p.second;
                break;
            }
        }
    }

    if (anchor == nullptr)
        return; // not found

    anchor->restore_timestamp();
    anchorQueue_.fix();
}

bool WorkingChain::has_link(Hash hash) {
    return (links_.find(hash) != links_.end());
}

auto WorkingChain::find_bad_header(const std::vector<BlockHeader>& headers) -> bool {
    for(auto& header: headers) {
        Hash header_hash = header.hash();
        if (contains(badHeaders_,header_hash))
            return true;
    }
    return false;
}

auto WorkingChain::accept_headers(const std::vector<BlockHeader>& headers, PeerId peerId) -> std::tuple<Penalty,RequestMoreHeaders> {
    bool requestMoreHeaders = false;

    if (find_bad_header(headers))
        return {Penalty::BadBlockPenalty, requestMoreHeaders};

    auto header_list = HeaderList::make(headers);

    auto [segments, penalty] = header_list->split_into_segments(); // todo: Erigon here pass also headerRaw

    if (penalty != Penalty::NoPenalty)
        return {penalty, requestMoreHeaders};

    for(auto& segment: segments) {
        requestMoreHeaders |= process_segment(segment, false, peerId);
    }

    return {Penalty::NoPenalty, requestMoreHeaders};
}

auto HeaderList::to_ref() -> std::vector<Header_Ref> {
    std::vector<Header_Ref> refs;
    for(Header_Ref i = headers_.begin(); i < headers_.end(); i++)
        refs.push_back(i);
    return refs;
}

std::tuple<bool,Penalty> HeaderList::childParentValidity(Header_Ref child, Header_Ref parent) {
    if (parent->number + 1 != child->number)
        return {false, Penalty::WrongChildBlockHeightPenalty};
    return {true, NoPenalty};
}

std::tuple<bool,Penalty> HeaderList::childrenParentValidity(const std::vector<Header_Ref>& children, Header_Ref parent) {
    for(auto& child: children) {
        auto [valid, penalty] = childParentValidity(child, parent);
        if (!valid)
            return {false, penalty};
    }
    return {true, Penalty::NoPenalty};
}

/*
// SplitIntoSegments converts message containing headers into a collection of chain segments
func (hd *HeaderDownload) SplitIntoSegments(headersRaw [][]byte, msg []*types.Header) ([]*ChainSegment, Penalty, error) {
	hd.lock.RLock()
	defer hd.lock.RUnlock()
	sort.Sort(HeadersByBlockHeight(msg))
	// Now all headers are order from the highest block height to the lowest
	var segments []*ChainSegment                         // Segments being built
	segmentMap := make(map[common.Hash]int)              // Mapping of the header hash to the index of the chain segment it belongs
	childrenMap := make(map[common.Hash][]*types.Header) // Mapping parent hash to the children
	dedupMap := make(map[common.Hash]struct{})           // Map used for detecting duplicate headers
	for i, header := range msg {
		headerHash := header.Hash()
		if _, bad := hd.badHeaders[headerHash]; bad {
			return nil, BadBlockPenalty, nil
		}
		if _, duplicate := dedupMap[headerHash]; duplicate {
			return nil, DuplicateHeaderPenalty, nil
		}
		dedupMap[headerHash] = struct{}{}
		var segmentIdx int
		children := childrenMap[headerHash]
		for _, child := range children {
			if valid, penalty := hd.childParentValid(child, header); !valid {
				return nil, penalty, nil
			}
		}
		if len(children) == 1 {
			// Single child, extract segmentIdx
			segmentIdx = segmentMap[headerHash]
		} else {
			// No children, or more than one child, create new segment
			segmentIdx = len(segments)
			segments = append(segments, &ChainSegment{})
		}
		segments[segmentIdx].Headers = append(segments[segmentIdx].Headers, header)
		segments[segmentIdx].HeadersRaw = append(segments[segmentIdx].HeadersRaw, headersRaw[i])
		segmentMap[header.ParentHash] = segmentIdx
		siblings := childrenMap[header.ParentHash]
		siblings = append(siblings, header)
		childrenMap[header.ParentHash] = siblings
	}
	return segments, NoPenalty, nil
}
 */


/*
 * SplitIntoSegments converts message containing headers into a collection of chain segments.
 * A message received from a peer may contain a collection of disparate headers (for example, in a response to the
 * skeleton query), or any branched chain bundle. So it needs to be split into chain segments.
 * SplitIntoSegments takes a collection of headers and return a collection of chain segments in a specific order.
 * This order is the ascending order of the lowest block height in the segment.
 * There may be many possible ways to split a chain bundle into segments, we choose one that is simple and that assures
 * this properties:
 *    - segments form a partial order
 *    - whatever part of the chain that becomes canonical it is not necessary to redo the process of division into segments
 */
auto HeaderList::split_into_segments() -> std::tuple<std::vector<Segment>, Penalty> {

    std::vector<Header_Ref> headers = to_ref();
    std::sort(headers.begin(), headers.end(), [](auto& h1, auto& h2){return h1->number > h2->number;}); // sort headers from the highest block height to the lowest

    std::vector<Segment> segments;
    std::map<Hash, size_t> segmentMap;
    std::map<Hash, std::vector<Header_Ref>> childrenMap;
    std::set<Hash> dedupMap;
    size_t segmentIdx = 0;

    for(auto& header: headers) {
        Hash header_hash = header->hash();

        if (contains(dedupMap, header_hash))
            return {{}, Penalty::DuplicateHeaderPenalty};

        dedupMap.insert(header_hash);
        auto children = childrenMap[header_hash];
        auto [valid, penalty] = HeaderList::childrenParentValidity(children, header);
        if (!valid) return {{}, penalty};

        if (children.size() == 1) {
            // Single child, extract segmentIdx
            segmentIdx = segmentMap[header_hash];
        }
        else {
            // No children, or more than one child, create new segment
            segmentIdx = segments.size();
            segments.emplace_back(shared_from_this());    // add a void segment
        }

        segments[segmentIdx].push_back(header);
        //segments[segmentIdx].headersRaw.push_back(headersRaw[i]); // todo: do we need this?

        segmentMap[header->parent_hash] = segmentIdx;

        auto& siblings = childrenMap[header->parent_hash];
        siblings.push_back(header);
    }

    return {segments, Penalty::NoPenalty};
}

/* implementation without Header_Ref
std::tuple<bool,Penalty> childParentValidity(const BlockHeader& child, const BlockHeader& parent) {
    if (parent.number + 1 != child.number)
        return {false, Penalty::WrongChildBlockHeightPenalty};
    return {true, NoPenalty};
}

std::tuple<bool,Penalty> childrenParentValidity(const std::vector<BlockHeader>& children, const BlockHeader& parent) {
    for(auto& child: children) {
        auto [valid, penalty] = childParentValidity(child, parent);
        if (!valid)
            return {false, penalty};
    }
    return {true, Penalty::NoPenalty};
}

auto WorkingChain::split_into_segments(const std::vector<BlockHeader>& headers) -> std::tuple<std::vector<Segment>, Penalty> {

    std::sort(headers.begin(), headers.end(), [](auto& h1, auto& h2){return h1.number > h2.number;}); // sort headers from the highest block height to the lowest

    std::vector<Segment> segments;
    std::map<Hash, int> segmentMap;
    std::map<Hash, std::vector<BlockHeader>> childrenMap;
    std::set<Hash> dedupMap;
    int segmentIdx = 0;

    for(auto& header: headers) {
        if (badHeaders_.contains(header.hash()))
            return {{}, Penalty::BadBlockPenalty};
        if (dedupMap.contains(header.hash()))
            return {{}, Penalty::DuplicateHeaderPenalty};
        dedupMap.insert(header.hash());
        auto children = childrenMap[header.hash()];

        auto [valid, penalty] = childrenParentValidity(children, header);
        if (!valid) return {{}, penalty};

        if (children.size() == 1) {
            // Single child, extract segmentIdx
            segmentIdx = segmentMap[header.hash()];
        }
        else {
            // No children, or more than one child, create new segment
            segmentIdx = segments.size();
            segments.emplace_back();    // add a void segment
        }

        segments[segmentIdx].headers.push_back(header); // todo: copy o reference?
        //segments[segmentIdx].headersRaw.push_back(headersRaw[i]); // todo: do we need this?

        segmentMap[header.parent_hash] = segmentIdx;

        auto& siblings = childrenMap[header.parent_hash];
        siblings.push_back(header);     // todo: copy o reference?
    }

    return {segments, Penalty::NoPenalty};
}
*/

/*
// ProcessSegment - handling single segment.
// If segment were processed by extendDown or newAnchor method, then it returns `requestMore=true`
// it allows higher-level algo immediately request more headers without waiting all stages precessing,
// speeds up visibility of new blocks
// It remember peerID - then later - if anchors created from segments will abandoned - this peerID gonna get Penalty
func (hd *HeaderDownload) ProcessSegment(segment *ChainSegment, newBlock bool, peerID string) (requestMore bool) {
	log.Debug("processSegment", "from", segment.Headers[0].Number.Uint64(), "to", segment.Headers[len(segment.Headers)-1].Number.Uint64())
	hd.lock.Lock()
	defer hd.lock.Unlock()
	foundAnchor, start := hd.findAnchors(segment)
	foundTip, end := hd.findLink(segment, start) // We ignore penalty because we will check it as part of PoW check
	if end == 0 {
		log.Debug("Duplicate segment")
		return
	}
	height := segment.Headers[len(segment.Headers)-1].Number.Uint64()
	hash := segment.Headers[len(segment.Headers)-1].Hash()
	if newBlock || hd.seenAnnounces.Seen(hash) {
		if height > hd.topSeenHeight {
			hd.topSeenHeight = height
		}
	}
	startNum := segment.Headers[start].Number.Uint64()
	endNum := segment.Headers[end-1].Number.Uint64()
	// There are 4 cases
	if foundAnchor {
		if foundTip {
			// Connect
			if err := hd.connect(segment, start, end); err != nil {
				log.Debug("Connect failed", "error", err)
				return
			}
			log.Debug("Connected", "start", startNum, "end", endNum)
		} else {
			// ExtendDown
			var err error
			if requestMore, err = hd.extend_down(segment, start, end); err != nil {
				log.Debug("ExtendDown failed", "error", err)
				return
			}
			log.Debug("Extended Down", "start", startNum, "end", endNum)
		}
	} else if foundTip {
		if end > 0 {
			// ExtendUp
			if err := hd.extendUp(segment, start, end); err != nil {
				log.Debug("ExtendUp failed", "error", err)
				return
			}
			log.Debug("Extended Up", "start", startNum, "end", endNum)
		}
	} else {
		// NewAnchor
		var err error
		if requestMore, err = hd.newAnchor(segment, start, end, peerID); err != nil {
			log.Debug("NewAnchor failed", "error", err)
			return
		}
		log.Debug("NewAnchor", "start", startNum, "end", endNum)
	}
	//log.Info(hd.anchorState())
	log.Debug("Link queue", "size", hd.linkQueue.Len())
	if hd.linkQueue.Len() > hd.linkLimit {
		log.Debug("Too many links, cutting down", "count", hd.linkQueue.Len(), "tried to add", end-start, "limit", hd.linkLimit)
	}
	for hd.linkQueue.Len() > hd.linkLimit {
		link := heap.Pop(hd.linkQueue).(*Link)
		delete(hd.links, link.hash)
		if parentLink, ok := hd.links[link.header.ParentHash]; ok {
			for i, n := range parentLink.next {
				if n == link {
					if i == len(parentLink.next)-1 {
						parentLink.next = parentLink.next[:i]
					} else {
						parentLink.next = append(parentLink.next[:i], parentLink.next[i+1:]...)
					}
					break
				}
			}
		}
		if anchor, ok := hd.anchors[link.header.ParentHash]; ok {
			for i, n := range anchor.links {
				if n == link {
					if i == len(anchor.links)-1 {
						anchor.links = anchor.links[:i]
					} else {
						anchor.links = append(anchor.links[:i], anchor.links[i+1:]...)
					}
					break
				}
			}
		}
	}
	select {
	case hd.DeliveryNotify <- struct{}{}:
	default:
	}

	return hd.requestChaining && requestMore
}

*/
auto WorkingChain::process_segment(const Segment& segment, bool is_a_new_block, PeerId peerId) -> RequestMoreHeaders {
    auto [foundAnchor, start] = find_anchor(segment);
    auto [foundTip, end] = find_link(segment, start);

    if (end == 0) {
        SILKWORM_LOG(LogLevel::Debug) << "WorkingChain: duplicate segment\n";
        return false;
    }

    auto lowest_header = segment.back();
    auto height = lowest_header->number;

    if (is_a_new_block || seenAnnounces_.get(Hash(lowest_header->hash())) != nullptr) {
        if (height > topSeenHeight_) topSeenHeight_ = height;
    }

    auto startNum = segment[start]->number;
    auto endNum = segment[end - 1]->number;

    //Segment::Slice segment_slice{segment.begin()+start, segment.begin()+end};  // require c++20 span
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
        }
        else if (foundTip) {
            if (end > 0 ) { // ExtendUp
                op = "extend up";
                extend_up(segment_slice);
            }
        }
        else { // NewAnchor
            op = "new anchor";
            requestMore = new_anchor(segment_slice, peerId);
        }
        SILKWORM_LOG(LogLevel::Debug) << "Segment: " << op << " start=" << startNum << " end=" << endNum << "\n";
    }
    catch(segment_cut_and_paste_error& e) {
        SILKWORM_LOG(LogLevel::Debug) << "Segment: " << op << " failure, reason:" << e.what() << "\n";
        return false;
    }

    reduce_links_to(link_limit);

    // select { case hd.DeliveryNotify <- struct{}{}: default: } // todo: translate

    return requestMore /* && hd.requestChaining */; // todo: translate requestChaining
}

void WorkingChain::reduce_links_to(size_t limit) {
    if (linkQueue_.size() <= limit)
        return; // does nothing

    SILKWORM_LOG(LogLevel::Debug) << "LinkQueue: too many links, cutting down from " << linkQueue_.size() << " to " << link_limit << "\n";

    while (linkQueue_.size() > limit) {
        auto link = linkQueue_.top();
        linkQueue_.pop();
        links_.erase(link->hash);
        // delete not needed, using shared_ptr

        auto parentLink_i = links_.find(link->header->parent_hash);
        if (parentLink_i != links_.end())
            parentLink_i->second->remove_child(link);

        auto anchor_i = anchors_.find(link->header->parent_hash);
        if (anchor_i != anchors_.end())
            anchor_i->second->remove_child(link);

    }
}

/*
// FindAnchors attempts to find anchors to which given chain segment can be attached to
func (hd *HeaderDownload) findAnchors(segment *ChainSegment) (found bool, start int) {
	// Walk the segment from children towards parents
	for i, header := range segment.Headers {
		// Check if the header can be attached to an anchor of a working tree
		if _, attaching := hd.anchors[header.Hash()]; attaching {
			return true, i
		}
	}
	return false, 0
}
*/

// find_anchors tries to finds the highest link the in the new segment that can be attached to an existing anchor
auto WorkingChain::find_anchor(const Segment& segment) -> std::tuple<Found, Start> { // todo: do we need a span?
    for (size_t i = 0; i < segment.size(); i++)
        if (anchors_.find(segment[i]->hash()) != anchors_.end()) // todo: hash() compute the value
            return {true, i};

    return {false, 0};
}

/*
// FindLink attempts to find a non-persisted link that given chain segment can be attached to.
func (hd *HeaderDownload) findLink(segment *ChainSegment, start int) (found bool, end int) {
	if _, duplicate := hd.getLink(segment.Headers[start].Hash()); duplicate {
		return false, 0
	}
	// Walk the segment from children towards parents
	for i, header := range segment.Headers[start:] {
		// Check if the header can be attached to any links
		if _, attaching := hd.getLink(header.ParentHash); attaching {
			return true, start + i + 1
		}
	}
	return false, len(segment.Headers)
}
 */
// find_link find the highest existing link (from start) that the new segment can be attached to
auto WorkingChain::find_link(const Segment& segment, size_t start) -> std::tuple<Found, End> { // todo: End o Header_Ref?
    auto duplicate_link = get_link(segment[start]->hash());
    if (duplicate_link)
        return {false, 0};
    for (size_t i = start; i < segment.size(); i++) {
        // Check if the header can be attached to any links
        auto attaching_link = get_link(segment[i]->parent_hash);
        if (attaching_link)
            return {true, i + 1}; // return the ordinal of the next link
    }
    return {false, segment.size()};
}

auto WorkingChain::get_link(Hash hash) -> std::optional<std::shared_ptr<Link>> {
    auto it = links_.find(hash);
    if (it != links_.end())
        return {it->second};
    return {};
}

/*
// Connect connects some working trees using anchors of some, and a link of another
func (hd *HeaderDownload) connect(segment *ChainSegment, start, end int) error {
	// Find attachment link again
	linkHeader := segment.Headers[end-1]
	// Find attachement anchors again
	anchorHeader := segment.Headers[start]
	attachmentLink, ok1 := hd.getLink(linkHeader.ParentHash)
	if !ok1 {
		return fmt.Errorf("connect attachment link not found for %x", linkHeader.ParentHash)
	}
	if attachmentLink.preverified && len(attachmentLink.next) > 0 {
		return fmt.Errorf("cannot connect to preverified link %d with children", attachmentLink.blockHeight)
	}
	anchor, ok2 := hd.anchors[anchorHeader.Hash()]
	if !ok2 {
		return fmt.Errorf("connect attachment anchors not found for %x", anchorHeader.Hash())
	}
	anchorPreverified := false
	for _, link := range anchor.links {
		if link.preverified {
			anchorPreverified = true
			break
		}
	}
	delete(hd.anchors, anchor.parentHash)
	// Iterate over headers backwards (from parents towards children)
	prevLink := attachmentLink
	for i := end - 1; i >= start; i-- {
		link := hd.addHeaderAsLink(segment.Headers[i], false ) // false = persisted
		prevLink.next = append(prevLink.next, link)
		prevLink = link
		if !anchorPreverified {
			if _, ok := hd.preverifiedHashes[link.hash]; ok {
				hd.markPreverified(link)
			}
		}
	}
	prevLink.next = anchor.links
	anchor.links = nil
	if anchorPreverified {
		// Mark the entire segment as preverified
		hd.markPreverified(prevLink)
	}
	if attachmentLink.persisted {
		link := hd.links[linkHeader.Hash()]
		hd.insertList = append(hd.insertList, link)
	}
	return nil
}
*/
void WorkingChain::connect(Segment::Slice segment_slice) { // throw segment_cut_and_paste_error
    using std::to_string;

    // the 3 following blocks are extend_up
    auto link_header = *segment_slice.rbegin(); // lowest header
    auto attachment_link = get_link(link_header->parent_hash);
    if (!attachment_link)
        throw segment_cut_and_paste_error("segment cut&paste error, connect attachment link not found for " +
                                          to_hex(link_header->parent_hash));
    if (attachment_link.value()->preverified && attachment_link.value()->next.size() > 0)
        throw segment_cut_and_paste_error("segment cut&paste error, cannot connect to preverified link " +
                                          to_string(attachment_link.value()->blockHeight) + " with children");

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link.value();
    for(auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        prev_link->next.push_back(link); // add link as next of the preceding
        prev_link = link;
        if (contains(preverifiedHashes_, link->hash))
            mark_as_preverified(link);
    }

    if (attachment_link.value()->persisted) {
        auto link = links_.find(link_header->hash());
        if (link != links_.end()) // todo: Erigon code assume true always, check!
            insertList_.push(link->second);
    }

    // todo: modularize this, his block is the same in extend_down
    auto anchor_header = *segment_slice.begin(); // highest header
    auto a = anchors_.find(anchor_header->hash());
    bool attaching = a != anchors_.end();
    if (!attaching)
        throw segment_cut_and_paste_error("segment cut&paste error, connect attachment anchors not found for " +
                                          to_hex(anchor_header->hash()));

    // todo: this block is the same in extend_down
    auto anchor = a->second;
    auto anchor_preverified = false;
    for (auto& link: anchor->links) {  // todo: use find_if
        if (link->preverified) {
            anchor_preverified = true;
            break;
        }
    }

    anchors_.erase(anchor->parentHash); // Anchor is removed from the map, but not from the anchorQueue
    // This is because it is hard to find the index under which the anchor is stored in the anchorQueue
    // But removal will happen anyway, in th function RequestMoreHeaders, if it disapppears from the map

    // todo: this block is also in "extend_down" method
    prev_link->next = std::move(anchor->links);
    anchor->links.clear();
    if (anchor_preverified)
        mark_as_preverified(prev_link); // Mark the entire segment as preverified


}

/*
// ExtendDown extends some working trees down from the anchor, using given chain segment
// it creates a new anchor and collects all the links from the attached anchors to it
func (hd *HeaderDownload) extendDown(segment *ChainSegment, start, end int) (bool, error) {
	// Find attachment anchor again
	anchorHeader := segment.Headers[start]
	if , attaching := hd.anchors[anchorHeader.Hash()]; attaching {
		anchorPreverified := false
		for _, link := range anchor.links {
			if link.preverified {
				anchorPreverified = true
				break
			}
		}
		newAnchorHeader := segment.Headers[end-1]
		var newAnchor *Anchor
		newAnchor, preExisting := hd.anchors[newAnchorHeader.ParentHash]
		if !preExisting {
			newAnchor = &Anchor{
				parentHash:  newAnchorHeader.ParentHash,
				timestamp:   0,
				peerID:      anchor.peerID,
				blockHeight: newAnchorHeader.Number.Uint64(),
			}
			if newAnchor.blockHeight > 0 {
				hd.anchors[newAnchorHeader.ParentHash] = newAnchor
				heap.Push(hd.anchorQueue, newAnchor)
			}
		}

		delete(hd.anchors, anchor.parentHash)
		// Add all headers in the segments as links to this anchor
		var prevLink *Link
		for i := end - 1; i >= start; i-- {
			link := hd.addHeaderAsLink(segment.Headers[i], false ) // false = persisted
			if prevLink == nil {
				newAnchor.links = append(newAnchor.links, link)
			} else {
				prevLink.next = append(prevLink.next, link)
			}
			prevLink = link
			if !anchorPreverified {
				if _, ok := hd.preverifiedHashes[link.hash]; ok {
					hd.markPreverified(link)
				}
			}
		}
		prevLink.next = anchor.links
		anchor.links = nil
		if anchorPreverified {
			// Mark the entire segment as preverified
			hd.markPreverified(prevLink)
		}
		return !preExisting, nil
	}
	return false, fmt.Errorf("extend_down attachment anchors not found for %x", anchorHeader.Hash())
}
 */
auto WorkingChain::extend_down(Segment::Slice segment_slice) -> RequestMoreHeaders {  // throw segment_cut_and_paste_error
    using std::to_string;

    auto anchor_header = *segment_slice.begin(); // highest header
    auto a = anchors_.find(anchor_header->hash());
    bool attaching = a != anchors_.end();
    if (!attaching)
        throw segment_cut_and_paste_error("segment cut&paste error, extend down attachment anchors not found for " +
                                          to_hex(anchor_header->hash()));

    auto anchor = a->second;
    auto anchor_preverified = false;
    for (auto& link: anchor->links) {  // todo: use find_if
        if (link->preverified) {
            anchor_preverified = true;
            break;
        }
    }

    anchors_.erase(anchor->parentHash); // Anchor is removed from the map, but not from the anchorQueue
    // This is because it is hard to find the index under which the anchor is stored in the anchorQueue
    // But removal will happen anyway, in th function RequestMoreHeaders, if it disapppears from the map

    // todo: modularize this block in "add_anchor_if_not_present"
    auto new_anchor_header = *segment_slice.rbegin(); // lowest header
    std::shared_ptr<Anchor> new_anchor;
    a = anchors_.find(new_anchor_header->parent_hash);
    bool pre_existing = a != anchors_.end();
    if (!pre_existing) {
        new_anchor = std::make_shared<Anchor>(*new_anchor_header, anchor->peerId);
        if (new_anchor->blockHeight > 0) {
            anchors_[new_anchor_header->parent_hash] = new_anchor;
            anchorQueue_.push(new_anchor);
        }
    }

    // todo: modularize this block
    // Iterate over headers backwards (from parents towards children)
    // Add all headers in the segments as links to this anchor
    std::shared_ptr<Link> prev_link;
    for(auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (!prev_link)
            anchor->links.push_back(link);  // add the link chain in the anchor
        else
            prev_link->next.push_back(link); // add link as next of the preceding
        prev_link = link;
        if (!anchor_preverified && contains(preverifiedHashes_, link->hash))
            mark_as_preverified(link);
    }

    // todo: this block is also in "connect" method
    prev_link->next = std::move(anchor->links);
    anchor->links.clear();
    if (anchor_preverified)
        mark_as_preverified(prev_link); // Mark the entire segment as preverified

    return !pre_existing;
}

/*
// ExtendUp extends a working tree up from the link, using given chain segment
func (hd *HeaderDownload) extendUp(segment *ChainSegment, start, end int) error {
	// Find attachment link again
	linkHeader := segment.Headers[end-1]
	attachmentLink, attaching := hd.getLink(linkHeader.ParentHash)
	if !attaching {
		return fmt.Errorf("extendUp attachment link not found for %x", linkHeader.ParentHash)
	}
	if attachmentLink.preverified && len(attachmentLink.next) > 0 {
		return fmt.Errorf("cannot extendUp from preverified link %d with children", attachmentLink.blockHeight)
	}
	// Iterate over headers backwards (from parents towards children)
	prevLink := attachmentLink
	for i := end - 1; i >= start; i-- {
		link := hd.addHeaderAsLink(segment.Headers[i], false ) // false = persisted
		prevLink.next = append(prevLink.next, link)
		prevLink = link
		if _, ok := hd.preverifiedHashes[link.hash]; ok {
			hd.markPreverified(link)
		}
	}

	if attachmentLink.persisted {
		link := hd.links[linkHeader.Hash()]
		hd.insertList = append(hd.insertList, link)
	}
	return nil
}
*/
void WorkingChain::extend_up(Segment::Slice segment_slice) {  // throw segment_cut_and_paste_error
    using std::to_string;

    // Find previous link to extend up with the segment
    auto link_header = *segment_slice.rbegin(); // lowest header
    auto attachment_link = get_link(link_header->parent_hash);
    if (!attachment_link)
        throw segment_cut_and_paste_error("segment cut&paste error, extend up attachment link not found for " +
                                                  to_hex(link_header->parent_hash));
    if (attachment_link.value()->preverified && attachment_link.value()->next.size() > 0)
        throw segment_cut_and_paste_error("segment cut&paste error, cannot extend up from preverified link " +
                                          to_string(attachment_link.value()->blockHeight) + " with children");

    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link = attachment_link.value();
    for(auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        prev_link->next.push_back(link); // add link as next of the preceding
        prev_link = link;
        if (contains(preverifiedHashes_, link->hash))
            mark_as_preverified(link);
    }

    if (attachment_link.value()->persisted) {
        auto link = links_.find(link_header->hash());
        if (link != links_.end()) // todo: Erigon code assume true always, check!
            insertList_.push(link->second);
    }
}

/*
// if anchor will be abandoned - given peerID will get Penalty
func (hd *HeaderDownload) newAnchor(segment *ChainSegment, start, end int, peerID string) (bool, error) {
	anchorHeader := segment.Headers[end-1]

	var anchor *Anchor
	anchor, preExisting := hd.anchors[anchorHeader.ParentHash]
	if !preExisting {
		if anchorHeader.Number.Uint64() < hd.highestInDb {
			return false, fmt.Errorf("new anchor too far in the past: %d, latest header in db: %d", anchorHeader.Number.Uint64(), hd.highestInDb)
		}
		if len(hd.anchors) >= hd.anchorLimit {
			return false, fmt.Errorf("too many anchors: %d, limit %d", len(hd.anchors), hd.anchorLimit)
		}
		anchor = &Anchor{
			parentHash:  anchorHeader.ParentHash,
			peerID:      peerID,
			timestamp:   0,
			blockHeight: anchorHeader.Number.Uint64(),
		}
		hd.anchors[anchorHeader.ParentHash] = anchor
		heap.Push(hd.anchorQueue, anchor)
	}
	// Iterate over headers backwards (from parents towards children)
	var prevLink *Link
	for i := end - 1; i >= start; i-- {
		header := segment.Headers[i]
		link := hd.addHeaderAsLink(header, false ) // false = persisted
		if prevLink == nil {
			anchor.links = append(anchor.links, link)
		} else {
			prevLink.next = append(prevLink.next, link)
		}
		prevLink = link
		if _, ok := hd.preverifiedHashes[link.hash]; ok {
			hd.markPreverified(link)
		}
	}
	return !preExisting, nil
}
 */
auto WorkingChain::new_anchor(Segment::Slice segment_slice, PeerId peerId) -> RequestMoreHeaders {  // throw segment_cut_and_paste_error
    using std::to_string;

    auto anchor_header = *segment_slice.rbegin(); // lowest header / todo: correct??? usually it is the linkHeader

    // todo: modularize this block in "add_anchor_if_not_present"
    // Add to anchors list if not
    auto a = anchors_.find(anchor_header->parent_hash);
    bool pre_existing = a != anchors_.end();
    std::shared_ptr<Anchor> anchor;
    if (!pre_existing) {
        if (anchor_header->number < highestInDb_)
            throw segment_cut_and_paste_error("segment cut&paste error, new anchor too far in the past: "
                                              + to_string(anchor_header->number) + ", latest header in db: " + to_string(highestInDb_));
        if (anchors_.size() >= anchor_limit)
            throw segment_cut_and_paste_error("segment cut&paste error, too many anchors: "
                + to_string(anchors_.size()) + ", limit: " + to_string(anchor_limit));

        anchor = std::make_shared<Anchor>(*anchor_header, peerId);
        anchors_[anchor_header->parent_hash] = anchor;
        anchorQueue_.push(anchor);
    }
    else { // pre-existing
        anchor = a->second;
    }

    // todo: modularize this block
    // Iterate over headers backwards (from parents towards children)
    std::shared_ptr<Link> prev_link;
    for(auto h = segment_slice.rbegin(); h != segment_slice.rend(); h++) {
        auto header = *h;
        bool persisted = false;
        auto link = add_header_as_link(*header, persisted);
        if (!prev_link)
            anchor->links.push_back(link);  // add the link chain in the anchor
        else
            prev_link->next.push_back(link); // add link as next of the preceding
        prev_link = link;
        if (contains(preverifiedHashes_, link->hash))
            mark_as_preverified(link);
    }

    return !pre_existing;
}

/*
// addHeaderAsLink wraps header into a link and adds it to either queue of persisted links or queue of non-persisted links
func (hd *HeaderDownload) addHeaderAsLink(header *types.Header, persisted bool) *Link {
	height := header.Number.Uint64()
	linkHash := header.Hash()
	link := &Link{
		blockHeight: height,
		hash:        linkHash,
		header:      header,
		persisted:   persisted,
	}
	hd.links[linkHash] = link
	if persisted {
		heap.Push(hd.persistedLinkQueue, link)
	} else {
		heap.Push(hd.linkQueue, link)
	}
	return link
}
 */
auto WorkingChain::add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link> {
    auto link = std::make_shared<Link>(header, persisted);
    links_[link->hash] = link;
    if (persisted)
        persistedLinkQueue_.push(link);
    else
        linkQueue_.push(link);

    return link;
}

/*
func (hd *HeaderDownload) markPreverified(link *Link) {
	// Go through all parent links that are not preveried and mark them too
	for link != nil && !link.preverified {
		link.preverified = true
		link = hd.links[link.header.ParentHash]
	}
}
 */

// Mark a link and all its ancestors as preverified
void WorkingChain::mark_as_preverified(std::shared_ptr<Link> link) {
    while (link) {
        link->preverified = true;
        auto parent = links_.find(link->header->parent_hash);
        link = (parent != links_.end() ? parent->second : nullptr);
    }
}

void WorkingChain::set_preverified_hashes(std::set<Hash>&& preverifiedHashes, BlockNum preverifiedHeight) {
    preverifiedHashes_ = std::move(preverifiedHashes);
    preverifiedHeight_ = preverifiedHeight;
}

}