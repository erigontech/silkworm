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

#ifndef SILKWORM_BODY_SEQUENCE_HPP
#define SILKWORM_BODY_SEQUENCE_HPP

#include <silkworm/chain/identity.hpp>

#include <silkworm/downloader/packets/new_block_packet.hpp>
#include <silkworm/downloader/packets/get_block_bodies_packet.hpp>

#include "db_tx.hpp"
#include "types.hpp"

namespace silkworm {

/** BodySequence represents the sequence of body that we are downloading.
 *  It has these responsibilities:
 *    - decide what bodies request (to peers)
 *    - collect bodies,
 *    - decide what bodies can be persisted on the db
 */
class BodySequence {
  public:
    BodySequence(const Db::ReadOnlyAccess&, const ChainIdentity&);
    ~BodySequence();

    // sync current state - this must be done at body forward
    void sync_current_state(BlockNum highest_body_in_db, BlockNum highest_header_in_db);

    //! core functionalities: trigger the internal algorithms to decide what bodies we miss
    using MinBlock = BlockNum;
    auto request_more_bodies(time_point_t tp, seconds_t timeout)
        -> std::tuple<std::vector<Hash>, std::vector<PeerPenalization>, MinBlock>;

    //! it needs to know if the request issued was not delivered
    void request_nack(const std::vector<Hash>&, seconds_t timeout);

    //! core functionalities: process received bodies
    using RequestMoreBodies = bool;
    Penalty accept_requested_bodies(const std::vector<BlockBody>&, uint64_t request_id, const PeerId&);

    //! core functionalities: process received block announcement
    Penalty accept_new_block(const Block&, const PeerId&);

    //! core functionalities: returns bodies that are ready to be persisted
    auto withdraw_ready_bodies() -> std::vector<Block>;

    // minor functionalities
    std::vector<NewBlockPacket>& announces_to_do();

    BlockNum highest_block_in_db();

  private:
    void recover_initial_state();
    void make_new_requests(std::vector<Hash>&, MinBlock&, time_point_t tp, seconds_t timeout);
    auto renew_stale_requests(std::vector<Hash>&, MinBlock&, time_point_t tp, seconds_t timeout)
        -> std::vector<PeerPenalization>;
    void add_to_announcements(BlockHeader header, BlockBody body);

    size_t outstanding_requests();

    static bool is_valid_body(const BlockHeader&, const BlockBody&);

    static constexpr BlockNum max_blocks_per_message = 128;
    static constexpr BlockNum max_outstanding_requests = 128;
    static constexpr BlockNum max_announced_blocks = 10000;

    struct PendingBodyRequest {
        Hash block_hash;
        BlockNum block_height{0};
        BlockHeader header;
        BlockBody body;
        time_point_t request_time;
        bool ready{false};
    };

    struct AnnouncedBlocks {
        void add(Block block);
        std::optional<BlockBody> remove(BlockNum bn);
      private:
        std::map<BlockNum, Block> blocks_;
    };

    using IncreasingHeightOrderedMap = std::map<BlockNum, PendingBodyRequest>; // default ordering: less<BlockNum>

    IncreasingHeightOrderedMap body_requests_;
    AnnouncedBlocks announced_blocks_;
    std::vector<NewBlockPacket> announcements_to_do_;

    Db::ReadOnlyAccess db_access_;
    const ChainIdentity& chain_identity_;

    BlockNum highest_body_in_db_{0};
    BlockNum headers_stage_height_{0};
};

}


#endif  // SILKWORM_BODY_SEQUENCE_HPP
