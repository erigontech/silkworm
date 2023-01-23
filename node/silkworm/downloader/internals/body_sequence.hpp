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

#include <list>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/packets/block_bodies_packet.hpp>
#include <silkworm/downloader/packets/get_block_bodies_packet.hpp>
#include <silkworm/downloader/packets/new_block_packet.hpp>

#include "chain_elements.hpp"
#include "statistics.hpp"
#include "types.hpp"

namespace silkworm {

struct BlockEx: public Block {
    Hash hash;
    Total_Difficulty td;
    bool to_announce{false};
};

using Blocks = std::vector<std::shared_ptr<BlockEx>>;


/** BodySequence represents the sequence of body that we are downloading.
 *  It has these responsibilities:
 *    - decide what bodies request (to peers)
 *    - collect bodies,
 *    - decide what bodies can be persisted on the db
 */
class BodySequence {
  public:
    explicit BodySequence();
    ~BodySequence() = default;

    // sync current state - this must be done at header forward
    void current_state(BlockNum highest_in_db);

        // set a downloading target - this must be done at body forward
    void download_bodies(const Headers& headers);

    //! core functionalities: trigger the internal algorithms to decide what bodies we miss
    using MinBlock = BlockNum;
    auto request_more_bodies(time_point_t tp, uint64_t active_peers)
        -> std::tuple<GetBlockBodiesPacket66, std::vector<PeerPenalization>, MinBlock>;

    //! it needs to know if the request issued was not delivered
    void request_nack(const GetBlockBodiesPacket66&);

    //! core functionalities: process received bodies
    Penalty accept_requested_bodies(BlockBodiesPacket66&, const PeerId&);

    //! core functionalities: process received block announcement
    Penalty accept_new_block(const Block&, const PeerId&);

    //! core functionalities: returns bodies that are ready to be persisted
    Blocks withdraw_ready_bodies();

    //! minor functionalities
    [[nodiscard]] bool has_completed() const;
    [[nodiscard]] BlockNum highest_block_in_output() const;
    [[nodiscard]] BlockNum highest_block_in_memory() const;
    [[nodiscard]] BlockNum lowest_block_in_memory() const;
    [[nodiscard]] BlockNum target_height() const;
    [[nodiscard]] size_t outstanding_requests(time_point_t tp) const;
    [[nodiscard]] size_t ready_bodies() const;
    [[nodiscard]] size_t requests() const;

    [[nodiscard]] const Download_Statistics& statistics() const;

    // downloading process tuning parameters
    static constexpr size_t kMaxInMemoryRequests = 400000;
    static constexpr BlockNum kMaxBlocksPerMessage = 128;  // go-ethereum client acceptance limit
    static constexpr BlockNum kMaxAnnouncedBlocks = 10000;

  protected:
    auto renew_stale_requests(GetBlockBodiesPacket66&, MinBlock&, time_point_t, seconds_t timeout)
        -> std::vector<PeerPenalization>;
    void make_new_requests(GetBlockBodiesPacket66&, BlockNum&, time_point_t, seconds_t timeout);

    static bool is_valid_body(const BlockHeader&, const BlockBody&);

    struct BodyRequest {
        uint64_t request_id{0};
        Hash block_hash;
        BlockNum block_height{0};
        BlockHeader header;
        BlockBody body;
        time_point_t request_time;
        bool ready{false};
        bool to_announce{false};
    };

    bool fulfill_from_announcements(BodyRequest&);

    struct AnnouncedBlocks {
        void add(Block block);
        std::optional<BlockBody> remove(BlockNum bn);
        size_t size();

      private:
        std::map<BlockNum, Block> blocks_;  // todo: only canonical blocks? check!
    };

    // using IncreasingHeightOrderedMap = std::map<BlockNum, BodyRequest>; // default ordering: less<BlockNum>
    struct IncreasingHeightOrderedRequestContainer : public std::multimap<BlockNum, BodyRequest> {
        using Impl = std::map<BlockNum, BodyRequest>;
        using Iter = Impl::iterator;

        std::list<Iter> find_by_request_id(uint64_t request_id);
        Iter find_by_hash(Hash oh, Hash tr);

        [[nodiscard]] BlockNum lowest_block() const;
        [[nodiscard]] BlockNum highest_block() const;
    };

    IncreasingHeightOrderedRequestContainer body_requests_;
    AnnouncedBlocks announced_blocks_;

    BlockNum highest_body_in_output_{0};
    BlockNum target_height_{0};
    time_point_t last_nack_;
    size_t ready_bodies_{0};
    Download_Statistics statistics_;
};

}  // namespace silkworm
