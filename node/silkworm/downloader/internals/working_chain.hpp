/*
   Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_WORKING_CHAIN_HPP
#define SILKWORM_WORKING_CHAIN_HPP

#include <cstdio>

#include <gsl/span>

#include <silkworm/common/lru_cache.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/downloader/packets/GetBlockHeadersPacket.hpp>
#include "preverified_hashes.hpp"

#include "chain_elements.hpp"
#include "header_only_state.hpp"
#include "persisted_chain.hpp"

namespace silkworm {

/*
 * WorkingChain represents the chain that we are downloading; it has these responsibilities:
 *    - decide what headers request (to peers) to extend the chain
 *    - collect headers,
 *    - organize headers in segments
 *    - extend/connect segments
 *    - decide what headers can be persisted on the db
 * A user of this class, i.e. the HeaderDownloader, must ask it for header requests (see request_skeleton(),
 * request_more_headers()). WorkingChain doesn't know anything about the process that must be used to communicate with
 * the peers that are outside, the downloader have the charge to do real requests to peers. And when the downloader
 * receive headers from some peers, because it asked or because there is a new header announcement, it must provide
 * headers to the WorkingChain (see accept_headers()). Also, the downloader periodically must call
 * withdraw_stable_headers() to see if the WorkingChain has headers ready to persist. This happens when it has headers
 * that: 1) are verified or pre-verified and 2) are connected with headers already persisted, so we are ready to extend
 * the chain that is persisted on the db. The alter ego of WorkingChain is the PersistedChain.
 *
 * WorkingChain organizes headers in memory as collection of "chain bundles". Each chain bundle consists of one anchor
 * and some chain links. Each link corresponds to a block header. Links are connected to each other by ParentHash
 * fields. If ParentHash of some links do not point to another link in the same bundle, they all must point to the
 * anchor of this bundle.
 *
 * WorkingChain has 2 logic to extend this collection of chain bundles:
 * - Skeleton query: request headers in a wide range, as seed to grow later, they become anchor without links
 * - Anchor extension query: request headers to extend anchors
 */
class WorkingChain {
  public:
    using ConsensusEngine = std::unique_ptr<consensus::IEngine>;

    explicit WorkingChain(ConsensusEngine);

    // load initial state from db - this must be done at creation time
    void recover_initial_state(Db::ReadOnlyAccess::Tx&);

    // sync current state - this must be done at header forward
    void sync_current_state(BlockNum highest_in_db);

    // status
    bool in_sync() const;
    BlockNum highest_block_in_db() const;
    BlockNum top_seen_block_height() const;
    void top_seen_block_height(BlockNum);
    size_t pending_links() const;
    size_t anchors() const;
    std::string human_readable_status() const;
    std::string dump_chain_bundles() const;

    // core functionalities: anchor collection
    // to collect anchor more quickly we do a skeleton request i.e. a request of many headers equally distributed in a
    // given range of block chain that we want to fill
    auto request_skeleton() -> std::optional<GetBlockHeadersPacket66>;

    // core functionalities: anchor extension
    // to complete a range of block chain we need to do a request of headers to extend up or down an anchor or a segment
    auto request_more_headers(time_point_t tp, seconds_t timeout)
        -> std::tuple<std::optional<GetBlockHeadersPacket66>, std::vector<PeerPenalization>>;
    // also we need to know if the request issued was not delivered
    void request_nack(const GetBlockHeadersPacket66& packet);

    // core functionalities: process receiving headers
    // when a remote peer satisfy our request we receive one or more header that will be processed to fill hole in the
    // block chain
    using RequestMoreHeaders = bool;
    auto accept_headers(const std::vector<BlockHeader>&, uint64_t requestId, const PeerId&) -> std::tuple<Penalty, RequestMoreHeaders>;

    // core functionalities: persist new headers that have persisted parent
    auto withdraw_stable_headers() -> Headers;

    // minor functionalities
    void save_external_announce(Hash hash);
    bool has_link(Hash hash);
    std::vector<Announce>& announces_to_do();
    void add_bad_headers(const std::set<Hash>& bads);
    void set_preverified_hashes(const PreverifiedHashes*);

  protected:
    static constexpr BlockNum max_len = 192;
    static constexpr BlockNum stride = 8 * max_len;
    static constexpr size_t anchor_limit = 512;
    static constexpr size_t link_total = 1024 * 1024;
    static constexpr size_t persistent_link_limit = link_total / 16;
    static constexpr size_t link_limit = link_total - persistent_link_limit;

    auto process_segment(const Segment&, bool is_a_new_block, const PeerId&) -> RequestMoreHeaders;

    using Start = size_t;
    using End = size_t;
    auto find_anchor(const Segment&) const -> std::tuple<std::optional<std::shared_ptr<Anchor>>, Start>;
    auto find_link(const Segment&, size_t start) const -> std::tuple<std::optional<std::shared_ptr<Link>>, End>;
    auto get_link(const Hash& hash) const -> std::optional<std::shared_ptr<Link>>;
    using DeepLink = std::shared_ptr<Link>;
    auto find_anchor(std::shared_ptr<Link> link) const -> std::tuple<std::optional<std::shared_ptr<Anchor>>, DeepLink>;

    void reduce_links_to(size_t limit);
    void reduce_persisted_links_to(size_t limit);

    using Pre_Existing = bool;
    void invalidate(std::shared_ptr<Anchor>);
    void remove(std::shared_ptr<Anchor>);
    bool find_bad_header(const std::vector<BlockHeader>&);
    auto add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link>;
    auto add_anchor_if_not_present(const BlockHeader& header, PeerId, bool check_limits)
        -> std::tuple<std::shared_ptr<Anchor>, Pre_Existing>;
    void mark_as_preverified(std::shared_ptr<Link>);
    size_t anchors_within_range(BlockNum max);
    BlockNum lowest_anchor_within_range(BlockNum bottom, BlockNum top);
    std::shared_ptr<Anchor> highest_anchor();

    enum VerificationResult { Preverified, Skip, Postpone, Accept };
    VerificationResult verify(const Link& link);

    void connect(std::shared_ptr<Link>, Segment::Slice, std::shared_ptr<Anchor>);
    auto extend_down(Segment::Slice, std::shared_ptr<Anchor>) -> RequestMoreHeaders;
    void extend_up(std::shared_ptr<Link>, Segment::Slice);
    auto new_anchor(Segment::Slice, PeerId) -> RequestMoreHeaders;

    OldestFirstAnchorQueue anchor_queue_;        // Priority queue of anchors used to sequence the header requests
    LinkMap links_;                              // Links by header hash
    AnchorMap anchors_;                          // Mapping from parentHash to collection of anchors
    OldestFirstLinkMap persisted_link_queue_;  // Priority queue of persisted links used to limit their number
    OldestFirstLinkQueue insert_list_;  // List of non-persisted links that can be inserted (their parent is persisted)
    BlockNum highest_in_db_;
    BlockNum top_seen_height_;
    std::set<Hash> bad_headers_;
    const PreverifiedHashes* preverified_hashes_;  // Set of hashes that are known to belong to canonical chain
    using Ignore = int;
    lru_cache<Hash, Ignore> seen_announces_;
    std::vector<Announce> announces_to_do_;
    ConsensusEngine consensus_engine_;
    CustomHeaderOnlyChainState chain_state_;
    time_point_t last_skeleton_request;

    uint64_t generate_request_id();
    uint64_t is_valid_request_id(uint64_t request_id);

    uint64_t request_id_prefix;
    uint64_t request_count = 0;

  public:
    struct Statistics {
        // headers status
        uint64_t requested_headers = 0;
        uint64_t received_headers = 0;
        uint64_t accepted_headers = 0;
        // not accepted
        uint64_t not_requested_headers = 0;
        uint64_t duplicated_headers = 0;
        uint64_t invalid_headers = 0;
        uint64_t bad_headers = 0;
        // skeleton condition
        std::string skeleton_condition;

        friend std::ostream& operator<<(std::ostream& os, const WorkingChain::Statistics& stats);
    } statistics_;
};

}  // namespace silkworm

#endif  // SILKWORM_WORKING_CHAIN_HPP
