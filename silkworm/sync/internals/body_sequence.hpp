// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <list>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/sync/messages/outbound_get_block_bodies.hpp>
#include <silkworm/sync/packets/block_bodies_packet.hpp>
#include <silkworm/sync/packets/new_block_packet.hpp>

#include "chain_elements.hpp"
#include "statistics.hpp"
#include "types.hpp"

namespace silkworm {

struct BlockEx : public Block {
    Hash hash;
    TotalDifficulty td;
    bool to_announce{false};
};

using Blocks = std::vector<std::shared_ptr<BlockEx>>;

inline std::vector<std::shared_ptr<Block>> to_plain_blocks(const Blocks& blocks) {
    std::vector<std::shared_ptr<Block>> result;
    for (const auto& block : blocks) {
        result.push_back(block);
    }
    return result;
}

/** BodySequence represents the sequence of body that we are downloading.
 *  It has these responsibilities:
 *    - decide what bodies request (to peers)
 *    - collect bodies,
 *    - decide what bodies can be persisted on the db
 */
class BodySequence {
  public:
    explicit BodySequence() = default;
    ~BodySequence() = default;

    // sync current state - this must be done at header forward
    void current_state(BlockNum max_in_db);

    // set a downloading target - this must be done at body forward
    void download_bodies(const Headers& headers);

    //! core functionalities: trigger the internal algorithms to decide what bodies we miss
    std::shared_ptr<OutboundMessage> request_bodies(time_point_t tp);

    //! it needs to know if the request issued was not delivered
    void request_nack(const GetBlockBodiesPacket66&);

    //! core functionalities: process received bodies
    Penalty accept_requested_bodies(BlockBodiesPacket66&, const PeerId&);

    //! core functionalities: process received block announcement
    Penalty accept_new_block(const Block&, const PeerId&);

    //! core functionalities: returns bodies that are ready to be persisted
    Blocks withdraw_ready_bodies();

    //! minor functionalities
    bool has_completed() const;
    BlockNum max_block_in_output() const;
    BlockNum max_block_in_memory() const;
    BlockNum lowest_block_in_memory() const;
    BlockNum target_block_num() const;
    size_t outstanding_requests(time_point_t tp) const;
    size_t ready_bodies() const;
    size_t requests() const;

    const DownloadStatistics& statistics() const;

    // downloading process tuning parameters
    static constexpr size_t kMaxInMemoryRequests = 400000;
    static constexpr BlockNum kMaxBlocksPerMessage = 128;  // go-ethereum client acceptance limit
    static constexpr BlockNum kMaxAnnouncedBlocks = 10000;

  protected:
    using MinBlock = BlockNum;
    std::vector<PeerPenalization> renew_stale_requests(GetBlockBodiesPacket66&, MinBlock&, time_point_t, seconds_t timeout);
    void make_new_requests(GetBlockBodiesPacket66&, MinBlock&, time_point_t, seconds_t timeout);

    static bool is_valid_body(const BlockHeader&, const BlockBody&);

    struct BodyRequest {
        uint64_t request_id{0};
        Hash block_hash;
        BlockNum block_num{0};
        BlockHeader header;
        BlockBody body;
        time_point_t request_time;
        bool ready{false};
        bool to_announce{false};
    };

    bool fulfill_from_announcements(BodyRequest&);

    struct AnnouncedBlocks {
        void add(Block block);
        std::optional<BlockBody> remove(BlockNum block_num);
        size_t size();

      private:
        std::map<BlockNum, Block> blocks_;  // todo: only canonical blocks? check!
    };

    // using IncreasingHeightOrderedMap = std::map<BlockNum, BodyRequest>; // default ordering: less<BlockNum>
    struct IncreasingHeightOrderedRequestContainer : public std::multimap<BlockNum, BodyRequest> {
        using Impl = std::map<BlockNum, BodyRequest>;
        using Iter = Impl::iterator;

        std::list<Iter> find_by_request_id(uint64_t request_id);
        Iter find_by_hash(Hash oh, Hash tr, std::optional<Hash> wr);

        BlockNum lowest_block() const;
        BlockNum max_block() const;
    };

    IncreasingHeightOrderedRequestContainer body_requests_;
    AnnouncedBlocks announced_blocks_;

    BlockNum max_body_in_output_{0};
    BlockNum target_block_num_{0};
    time_point_t last_nack_;
    size_t ready_bodies_{0};
    DownloadStatistics statistics_;
    std::string retrieval_condition_;
};

}  // namespace silkworm
