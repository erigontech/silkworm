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
#include "header_retrieval.hpp"
#include "random_number.hpp"

namespace silkworm {


class segment_cut_and_paste_error: public std::logic_error {
  public:
    segment_cut_and_paste_error() : std::logic_error("segment cut&paste error, unknown reason") {}
    segment_cut_and_paste_error(const std::string& reason) : std::logic_error(reason) {}
};


WorkingChain::WorkingChain(): highestInDb_(0), topSeenHeight_(0) {
}

WorkingChain::WorkingChain(BlockNum highestInDb, BlockNum topSeenHeight): highestInDb_(highestInDb), topSeenHeight_(topSeenHeight) {
}

void WorkingChain::highest_block_in_db(BlockNum n) {
    highestInDb_ = n;
}
BlockNum WorkingChain::highest_block_in_db() {
    return highestInDb_;
}
void WorkingChain::top_seen_block_height(BlockNum n) {
    topSeenHeight_ = n;
}
BlockNum WorkingChain::top_seen_block_height() {
    return topSeenHeight_;
}

BlockNum WorkingChain::height_reached() {
    return 0;   // todo: implement!
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
void WorkingChain::recover_from_db(DbTx& db) {
    HeaderRetrieval headers(db);
    auto head_height = headers.head_height();
    highest_block_in_db(head_height); // the second limit will be set at the each block announcements

    // todo: implements!
}

/*
// HeadersForward progresses Headers stage in the forward direction
func HeadersForward(
	s *StageState,
	u Unwinder,
	ctx context.Context,
	tx ethdb.RwTx,
	cfg HeadersCfg,
	initialCycle bool,
	test bool, // Set to true in tests, allows the stage to fail rather than wait indefinitely
) error {
	var headerProgress uint64
	var err error
	useExternalTx := tx != nil
	if !useExternalTx {
		tx, err = cfg.db.BeginRw(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	if err = cfg.hd.ReadProgressFromDb(tx); err != nil {
		return err
	}
	cfg.hd.SetFetching(true)
	defer cfg.hd.SetFetching(false)
	headerProgress = cfg.hd.Progress()
	logPrefix := s.LogPrefix()
	// Check if this is called straight after the unwinds, which means we need to create new canonical markings
	hash, err := rawdb.ReadCanonicalHash(tx, headerProgress)
	if err != nil {
		return err
	}
	logEvery := time.NewTicker(logInterval)
	defer logEvery.Stop()
	if hash == (common.Hash{}) {
		headHash := rawdb.ReadHeadHeaderHash(tx)
		if err = fixCanonicalChain(logPrefix, logEvery, headerProgress, headHash, tx); err != nil {
			return err
		}
		if !useExternalTx {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
		s.Done()
		return nil
	}

	log.Info(fmt.Sprintf("[%s] Waiting for headers...", logPrefix), "from", headerProgress)

	localTd, err := rawdb.ReadTd(tx, hash, headerProgress)
	if err != nil {
		return err
	}
	headerInserter := headerdownload.NewHeaderInserter(logPrefix, localTd, headerProgress)
	cfg.hd.SetHeaderReader(&chainReader{config: &cfg.chainConfig, tx: tx})

	var peer []byte
	stopped := false
	prevProgress := headerProgress
	for !stopped {
		currentTime := uint64(time.Now().Unix())
		req, penalties := cfg.hd.RequestMoreHeaders(currentTime)
		if req != nil {
			peer = cfg.headerReqSend(ctx, req)
			if peer != nil {
				cfg.hd.SentRequest(req, currentTime, 5 ) // 5 = timeout
				log.Debug("Sent request", "height", req.Number)
			}
		}
		cfg.penalize(ctx, penalties)
		maxRequests := 64 // Limit number of requests sent per round to let some headers to be inserted into the database
		for req != nil && peer != nil && maxRequests > 0 {
			req, penalties = cfg.hd.RequestMoreHeaders(currentTime)
			if req != nil {
				peer = cfg.headerReqSend(ctx, req)
				if peer != nil {
					cfg.hd.SentRequest(req, currentTime, 5 ) // 5 = timeout
					log.Debug("Sent request", "height", req.Number)
				}
			}
			cfg.penalize(ctx, penalties)
			maxRequests--
		}

		// Send skeleton request if required
		req = cfg.hd.RequestSkeleton()
		if req != nil {
			peer = cfg.headerReqSend(ctx, req)
			if peer != nil {
				log.Debug("Sent skeleton request", "height", req.Number)
			}
		}
		// Load headers into the database
		var inSync bool
		if inSync, err = cfg.hd.InsertHeaders(headerInserter.FeedHeaderFunc(tx), logPrefix, logEvery.C); err != nil {
			return err
		}
		announces := cfg.hd.GrabAnnounces()
		if len(announces) > 0 {
			cfg.announceNewHashes(ctx, announces)
		}
		if headerInserter.BestHeaderChanged() { // We do not break unless there best header changed
			if !initialCycle {
				// if this is not an initial cycle, we need to react quickly when new headers are coming in
				break
			}
			// if this is initial cycle, we want to make sure we insert all known headers (inSync)
			if inSync {
				break
			}
		}
		if test {
			break
		}
		timer := time.NewTimer(1 * time.Second)
		select {
		case <-ctx.Done():
			stopped = true
		case <-logEvery.C:
			progress := cfg.hd.Progress()
			logProgressHeaders(logPrefix, prevProgress, progress)
			prevProgress = progress
		case <-timer.C:
			log.Trace("RequestQueueTime (header) ticked")
		case <-cfg.hd.DeliveryNotify:
			log.Debug("headerLoop woken up by the incoming request")
		}
		timer.Stop()
	}
	if headerInserter.Unwind() {
		if err := u.UnwindTo(headerInserter.UnwindPoint(), tx, common.Hash{}); err != nil {
			return fmt.Errorf("%s: failed to unwind to %d: %w", logPrefix, headerInserter.UnwindPoint(), err)
		}
	} else if headerInserter.GetHighest() != 0 {
		if err := fixCanonicalChain(logPrefix, logEvery, headerInserter.GetHighest(), headerInserter.GetHighestHash(), tx); err != nil {
			return fmt.Errorf("%s: failed to fix canonical chain: %w", logPrefix, err)
		}
	}
	s.Done()
	if !useExternalTx {
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	if stopped {
		return common.ErrStopped
	}
	// We do not print the followin line if the stage was interrupted
	log.Info(fmt.Sprintf("[%s] Processed", logPrefix), "highest inserted", headerInserter.GetHighest(), "age", common.PrettyAge(time.Unix(int64(headerInserter.GetHighestTimestamp()), 0)))
	stageHeadersGauge.Update(int64(cfg.hd.Progress()))
	return nil
}
*/
std::optional<GetBlockHeadersPacket66> WorkingChain::headers_forward() {
    // todo: implements!

    //auto [packet, penalties] = request_more_headers();
    // when the packet is sent we need to update some structures here

    // ...

    // only for test:
    return request_skeleton();
}

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
std::optional<GetBlockHeadersPacket66> WorkingChain::request_more_headers() {
    // time = currentTime
    // todo: implement!
    return {};
}

void WorkingChain::save_external_announce(Hash) {
    // Erigon implementation:
    // hd.seenAnnounces.Add(hash)
    // todo: implement!
    SILKWORM_LOG(LogLevel::Warn) << "SelfExtendingChain::save_external_announce() not implemented yet\n";
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
            segments.push_back(Segment(shared_from_this()));    // add a void segment
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
auto WorkingChain::process_segment(const Segment& segment, IsANewBlock isANewBlock, PeerId peerId) -> RequestMoreHeaders {
    auto [foundAnchor, start] = find_anchor(segment);
    auto [foundTip, end] = find_link(segment, start);

    if (end == 0) {
        SILKWORM_LOG(LogLevel::Debug) << "WorkingChain: duplicate segment\n";
        return false;
    }

    auto lowest_header = segment.back();
    auto height = lowest_header->number;

    if (isANewBlock /*|| hd.seenAnnounces.Seen(lowest_header->hash())*/) {  // todo: translate seenAnnounces
        if (height > topSeenHeight_) topSeenHeight_ = height;
    }

    auto startNum = segment[start]->number;
    auto endNum = segment[end - 1]->number;

    //Segment::Slice segment_slice{segment.begin()+start, segment.begin()+end};  // todo: remove, require c++20 span
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

    reduce_links();

    // select { case hd.DeliveryNotify <- struct{}{}: default: } // todo: translate

    return requestMore /* && hd.requestChaining */; // todo: translate requestChaining
}

void WorkingChain::reduce_links() {
    if (linkQueue_.size() <= link_limit)
        return; // does nothing

    SILKWORM_LOG(LogLevel::Debug) << "LinkQueue: too many links, cutting down from " << linkQueue_.size() << " to " << link_limit << "\n";

    while (linkQueue_.size() > link_limit) {
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
            insertList_.push_back(link->second);
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
            insertList_.push_back(link->second);
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
}