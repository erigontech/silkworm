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

#include <cstdio>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/sync/messages/outbound_get_block_headers.hpp>

#include "chain_elements.hpp"
#include "header_only_state.hpp"
#include "statistics.hpp"

namespace silkworm {

/** HeaderChain represents the chain that we are downloading.
 * It has these responsibilities:
 *    - decide what headers request (to peers) to extend the chain
 *    - collect headers,
 *    - organize headers in segments
 *    - extend/connect segments
 *    - decide what headers can be persisted on the db
 * A user of this class, i.e. the HeaderDownloader, must ask it for header requests (see request_skeleton(),
 * request_more_headers()). HeaderChain doesn't know anything about the process that must be used to communicate with
 * the peers that are outside, the sync have the charge to do real requests to peers. And when the sync
 * receive headers from some peers, because it asked or because there is a new header announcement, it must provide
 * headers to the HeaderChain (see accept_headers()). Also, the sync periodically must call
 * withdraw_stable_headers() to see if the HeaderChain has headers ready to persist. This happens when it has headers
 * that: 1) are verified or pre-verified and 2) are connected with headers already persisted, so we are ready to extend
 * the chain that is persisted on the db. The alter ego of WorkingChain is the HeaderPersistence.
 *
 * HeaderChain organizes headers in memory as collection of "chain bundles". Each chain bundle consists of one anchor
 * and some chain links. Each link corresponds to a block header. Links are connected to each other by ParentHash
 * fields. If ParentHash of some links do not point to another link in the same bundle, they all must point to the
 * anchor of this bundle.
 *
 * HeaderChain has 2 logic to extend this collection of chain bundles:
 * - Skeleton query: request headers in a wide range, as seed to grow later, they become anchor without links
 * - Anchor extension query: request headers to extend anchors
 */
class HeaderChain {
  public:
    explicit HeaderChain(const ChainConfig&);

    explicit HeaderChain(protocol::RuleSetPtr);  // alternative constructor

    // sync current state - this must be done at header forward
    void initial_state(const std::vector<BlockHeader>& last_headers);
    void current_state(BlockNum highest_in_db);
    // void downloading_target(BlockNum height) { downloading_target_ = height; }

    // status
    bool in_sync() const;
    BlockNum highest_block_in_db() const;
    BlockNum top_seen_block_height() const;
    void top_seen_block_height(BlockNum);
    std::pair<BlockNum, BlockNum> anchor_height_range() const;
    size_t pending_links() const;
    size_t anchors() const;
    size_t outstanding_requests(time_point_t tp) const;
    const Download_Statistics& statistics() const;

    // core functionalities: requesting new headers
    std::shared_ptr<OutboundMessage> request_headers(time_point_t);

    // core functionalities: add a new header
    std::shared_ptr<OutboundMessage> add_header(const BlockHeader& anchor, time_point_t);

    // also we need to know if the request issued was not delivered
    void request_nack(const GetBlockHeadersPacket66& packet);

    // core functionalities: process receiving headers
    // when a remote peer satisfy our request we receive one or more headers that will be processed
    using RequestMoreHeaders = bool;
    std::tuple<Penalty, RequestMoreHeaders> accept_headers(const std::vector<BlockHeader>&, uint64_t requestId, const PeerId&);

    // core functionalities: process header announcement
    std::optional<GetBlockHeadersPacket66> save_external_announce(Hash hash);

    // core functionalities: persist new headers that have persisted parent
    Headers withdraw_stable_headers();

    // minor functionalities
    bool has_link(Hash hash);
    std::vector<Announce>& announces_to_do();
    void add_bad_headers(const std::set<Hash>& bads);
    void set_preverified_hashes(PreverifiedHashes&);

  protected:
    static constexpr BlockNum max_len = 192;
    static constexpr BlockNum stride = 8 * max_len;
    static constexpr size_t anchor_limit = 512;
    static constexpr size_t link_total = 1024 * 1024;
    static constexpr size_t persistent_link_limit = link_total / 16;
    static constexpr size_t link_limit = link_total - persistent_link_limit;
    static constexpr seconds_t skeleton_req_interval{30};
    static constexpr seconds_t extension_req_timeout{30};

    // anchor collection: to collect headers more quickly we request headers in a wide range, as seed to grow later
    std::shared_ptr<OutboundMessage> anchor_skeleton_request(time_point_t);

    // anchor extension: to extend an anchor we do a request of many headers that are children of the anchor
    std::shared_ptr<OutboundMessage> anchor_extension_request(time_point_t);

    // process a segment of headers
    RequestMoreHeaders process_segment(const Segment&, bool is_a_new_block, const PeerId&);

    using Start = size_t;
    using End = size_t;
    std::tuple<std::optional<std::shared_ptr<Anchor>>, Start> find_anchor(const Segment&) const;
    std::tuple<std::optional<std::shared_ptr<Link>>, End> find_link(const Segment&, size_t start) const;
    std::optional<std::shared_ptr<Link>> get_link(const Hash& hash) const;
    using DeepLink = std::shared_ptr<Link>;
    std::tuple<std::optional<std::shared_ptr<Anchor>>, DeepLink> find_anchor(const std::shared_ptr<Link>& link) const;

    void reduce_links_to(size_t limit);
    void reduce_persisted_links_to(size_t limit);

    using Pre_Existing = bool;
    void invalidate(const std::shared_ptr<Anchor>&);
    void remove(const std::shared_ptr<Anchor>&);
    bool find_bad_header(const std::vector<BlockHeader>&);
    std::shared_ptr<Link> add_header_as_link(const BlockHeader& header, bool persisted);
    std::tuple<std::shared_ptr<Anchor>, Pre_Existing> add_anchor_if_not_present(const BlockHeader& header, PeerId, bool check_limits);
    void mark_as_preverified(std::shared_ptr<Link>);
    void compute_last_preverified_hash();
    size_t anchors_within_range(BlockNum max);
    std::optional<BlockNum> lowest_anchor_within_range(BlockNum bottom, BlockNum top);
    std::shared_ptr<Anchor> highest_anchor();
    void set_target_block(BlockNum);

    enum VerificationResult {
        Preverified,
        Skip,
        Postpone,
        Accept
    };
    VerificationResult verify(const Link& link);

    void connect(const std::shared_ptr<Link>&, Segment::Slice, const std::shared_ptr<Anchor>&);
    RequestMoreHeaders extend_down(Segment::Slice, const std::shared_ptr<Anchor>&);
    void extend_up(const std::shared_ptr<Link>&, Segment::Slice);
    RequestMoreHeaders new_anchor(Segment::Slice, PeerId);

    OldestFirstAnchorQueue anchor_queue_;      // Priority queue of anchors used to sequence the header requests
    LinkMap links_;                            // Links by header hash
    AnchorMap anchors_;                        // Mapping from parentHash to collection of anchors
    OldestFirstLinkMap persisted_link_queue_;  // Priority queue of persisted links used to limit their number
    OldestFirstLinkQueue insert_list_;         // List of non-persisted links that can be inserted (their parent is persisted)
    BlockNum highest_in_db_;
    BlockNum top_seen_height_;
    std::optional<BlockNum> target_block_;
    std::set<Hash> bad_headers_;
    PreverifiedHashes& preverified_hashes_;  // Set of hashes that are known to belong to canonical chain
    BlockNum last_preverified_hash_{0};
    using Ignore = int;
    lru_cache<Hash, Ignore> seen_announces_;
    std::vector<Announce> announces_to_do_;
    protocol::RuleSetPtr rule_set_;
    CustomHeaderOnlyChainState chain_state_;
    time_point_t last_skeleton_request_;
    time_point_t last_nack_;

    uint64_t generate_request_id();
    uint64_t is_valid_request_id(uint64_t request_id) const;

    uint64_t request_id_prefix;
    uint64_t request_count = 0;

    Download_Statistics statistics_;
    std::string skeleton_condition_;
    std::string extension_condition_;
};

}  // namespace silkworm
