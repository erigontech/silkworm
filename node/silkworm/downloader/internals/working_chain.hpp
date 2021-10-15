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

#ifndef SILKWORM_WORKING_CHAIN_HPP
#define SILKWORM_WORKING_CHAIN_HPP

#include <gsl/span>

#include <silkworm/common/lru_cache.hpp>
#include <silkworm/downloader/packets/GetBlockHeadersPacket.hpp>

#include "chain_elements.hpp"
#include "persisted_chain.hpp"

namespace silkworm {

class WorkingChain {  // tentative name - todo: improve!
  public:
    WorkingChain();

    // load initial state from db
    void recover_initial_state(Db::ReadOnlyAccess::Tx&);

    // sync current state
    void sync_current_state(BlockNum highest_in_db);

    // status
    bool in_sync() const;
    BlockNum highest_block_in_db() const;
    BlockNum top_seen_block_height() const;
    void top_seen_block_height(BlockNum);
    std::string human_readable_status() const;

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
    auto accept_headers(const std::vector<BlockHeader>&, PeerId) -> std::tuple<Penalty, RequestMoreHeaders>;

    // core functionalities: persist new headers that have persisted parent
    auto withdraw_stable_headers() -> Headers;

    // minor functionalities
    void save_external_announce(Hash hash);
    bool has_link(Hash hash);
    std::vector<Announce>& announces_to_do();
    void add_bad_headers(std::set<Hash>);

  protected:
    static constexpr BlockNum max_len = 192;
    static constexpr BlockNum stride = 8 * max_len;
    static constexpr size_t anchor_limit = 512;
    static constexpr size_t link_total = 1024 * 1024;
    static constexpr size_t persistent_link_limit = link_total / 16;
    static constexpr size_t link_limit = link_total - persistent_link_limit;

    auto process_segment(const Segment&, bool is_a_new_block, PeerId) -> RequestMoreHeaders;

    using Found = bool;
    using Start = size_t;
    using End = size_t;
    auto find_anchor(const Segment&) -> std::tuple<Found, Start>;
    auto find_link(const Segment&, size_t start) -> std::tuple<Found, End>;
    auto get_link(Hash hash) -> std::optional<std::shared_ptr<Link>>;

    void reduce_links_to(size_t limit);
    void reduce_persisted_links_to(size_t limit);

    void invalidate(Anchor&);
    bool find_bad_header(const std::vector<BlockHeader>&);
    auto add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link>;
    void mark_as_preverified(std::shared_ptr<Link>);

    void set_preverified_hashes(std::set<Hash>&& preverifiedHashes, BlockNum preverifiedHeight);

    using Error = int;
    void connect(Segment::Slice);                                   // throw segment_cut_and_paste_error
    auto extend_down(Segment::Slice) -> RequestMoreHeaders;         // throw segment_cut_and_paste_error
    void extend_up(Segment::Slice);                                 // throw segment_cut_and_paste_error
    auto new_anchor(Segment::Slice, PeerId) -> RequestMoreHeaders;  // throw segment_cut_and_paste_error

    YoungestFirstLinkQueue linkQueue_;         // Priority queue of non-persisted links used to limit their number
    OldestFirstAnchorQueue anchorQueue_;       // Priority queue of anchors used to sequence the header requests
    LinkMap links_;                            // Links by header hash
    AnchorMap anchors_;                        // Mapping from parentHash to collection of anchors
    OldestFirstLinkQueue persistedLinkQueue_;  // Priority queue of persisted links used to limit their number
    LinkLIFOQueue insertList_;  // List of non-persisted links that can be inserted (their parent is persisted)
    BlockNum highestInDb_;
    BlockNum topSeenHeight_;
    std::set<Hash> badHeaders_;
    std::set<Hash> preverifiedHashes_;  // Set of hashes that are known to belong to canonical chain
    BlockNum preverifiedHeight_{0};
    using Ignore = int;
    lru_cache<Hash, Ignore> seenAnnounces_;
    std::vector<Announce> announcesToDo_;
};

class ConsensusProto {  // todo: replace with correct implementation
  public:
    enum VerificationResult { VERIFIED, FUTURE_BLOCK, VERIFICATION_ERROR };

    static VerificationResult verify(const BlockHeader&) {
        // todo: implement, use seal = true
        return VERIFIED;
    };
};

}  // namespace silkworm

#endif  // SILKWORM_WORKING_CHAIN_HPP
