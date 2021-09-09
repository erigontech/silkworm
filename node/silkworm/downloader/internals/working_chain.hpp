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

#include <silkworm/downloader/packets/GetBlockHeadersPacket.hpp>

#include "chain_elements.hpp"

namespace silkworm {

class WorkingChain {  // tentative name - todo: improve!
  public:
    WorkingChain();  // todo: ok???
    WorkingChain(BlockNum highestInDb, BlockNum topSeenHeight);

    // load from db
    void recover_from_db(DbTx&); // todo: make it private and call in the constructor?

    // status
    void highest_block_in_db(BlockNum n);
    BlockNum highest_block_in_db();
    void top_seen_block_height(BlockNum n);
    BlockNum top_seen_block_height();

    BlockNum height_reached();

    // core functionalities: anchor collection
    // to collect anchor more quickly we do a skeleton request i.e. a request of many headers equally distributed in a
    // given range of block chain that we want to fill
    std::optional<GetBlockHeadersPacket66> request_skeleton();

    // core functionalities: anchor extension
    // to complete a range of block chain we need to do a request of headers to extend up or down an anchor or a segment
    std::tuple<std::optional<GetBlockHeadersPacket66>,
               std::vector<PeerPenalization>> request_more_headers(time_point_t tp, seconds_t timeout);
    // also we need to know if the request issued was not delivered
    void request_nack(const GetBlockHeadersPacket66& packet);

    // core functionalities: process receiving headers
    // when a remote peer satisfy our request we receive one or more header that will be processed to fill hole in the
    // block chain
    using RequestMoreHeaders = bool;
    std::tuple<Penalty,RequestMoreHeaders> accept_headers(const std::vector<BlockHeader>&, PeerId);

    // ...
    void save_external_announce(Hash hash);
    bool has_link(Hash hash);

  protected:
    static constexpr BlockNum max_len = 192;
    static constexpr BlockNum stride = 8 * max_len;
    static constexpr size_t anchor_limit = 512;
    static constexpr size_t link_total = 1024*1024;
    static constexpr size_t persistent_link_limit = link_total / 16;
    static constexpr size_t link_limit = link_total - persistent_link_limit;

    using IsANewBlock = bool;
    auto process_segment(const Segment&, IsANewBlock, PeerId) -> RequestMoreHeaders;

    using Found = bool; using Start = size_t; using End = size_t;
    auto find_anchor(const Segment&)                         -> std::tuple<Found, Start>;
    auto find_link(const Segment&, size_t start)             -> std::tuple<Found, End>;
    auto get_link(Hash hash)                                 -> std::optional<std::shared_ptr<Link>>;
    void reduce_links();
    void invalidate(Anchor&);
    bool find_bad_header(const std::vector<BlockHeader>&);
    auto add_header_as_link(const BlockHeader& header, bool persisted) -> std::shared_ptr<Link>;
    void mark_as_preverified(std::shared_ptr<Link>);

    using Error = int;
    void connect(Segment::Slice);                                 // throw segment_cut_and_paste_error
    auto extend_down(Segment::Slice) -> RequestMoreHeaders;        // throw segment_cut_and_paste_error
    void extend_up(Segment::Slice);                                // throw segment_cut_and_paste_error
    auto new_anchor(Segment::Slice, PeerId) -> RequestMoreHeaders; // throw segment_cut_and_paste_error

    Oldest_First_Link_Queue persistedLinkQueue_; // Priority queue of persisted links used to limit their number
    Youngest_First_Link_Queue linkQueue_;        // Priority queue of non-persisted links used to limit their number
    Oldest_First_Anchor_Queue anchorQueue_;      // Priority queue of anchors used to sequence the header requests
    Link_Map links_;                             // Links by header hash
    Anchor_Map anchors_;                         // Mapping from parentHash to collection of anchors
    Link_List insertList_;                       // List of non-persisted links that can be inserted (their parent is persisted)
    BlockNum highestInDb_;
    BlockNum topSeenHeight_;
    std::set<Hash> badHeaders_;
    std::set<Hash> preverifiedHashes_; // todo: fill! // Set of hashes that are known to belong to canonical chain
};

}

#endif  // SILKWORM_WORKING_CHAIN_HPP
