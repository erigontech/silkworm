/*
Copyright 2020-2022 The Silkworm Authors

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

#include "body_sequence.hpp"

#include <algorithm>

#include <catch2/catch.hpp>

#include <silkworm/chain/genesis.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/db/genesis.hpp>

#include "body_sequence.hpp"

namespace silkworm {
// Useful definitions
// ----------------------------------------------------------------------------

class BodySequence_ForTest : public BodySequence {
  public:
    // inheriting constructor
    using BodySequence::BodySequence;
    // publication of internal members to test methods functioning
    using BodySequence::body_requests_;
    using BodySequence::PendingBodyRequest;
    using BodySequence::outstanding_bodies;
};

TEST_CASE("body downloading", "[silkworm][downloader][BodySequence]") {
    using namespace std;
    using namespace std::chrono_literals;
    using intx::operator""_u256;

    test::Context context;
    auto& txn{context.txn()};

    bool allow_exceptions = false;

    auto chain_identity = ChainIdentity::mainnet;

    // add genesis to db
    auto source_data = silkworm::read_genesis_data(chain_identity.chain.chain_id);
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
    db::initialize_genesis(txn, genesis_json, allow_exceptions);

    // add header 1 to db
    std::string raw_header1 =
        "f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41a"
        "d312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353"
        "857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e8"
        "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f"
        "6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef"
        "1ec4";
    std::optional<Bytes> encoded_header1 = from_hex(raw_header1);
    BlockHeader header1;
    ByteView encoded_view = encoded_header1.value();
    [[maybe_unused]] auto result = rlp::decode(encoded_view, header1);

    Hash header1_hash = header1.hash();
    // mainnet_block1_hash = Hash::from_hex("88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6");
    db::write_canonical_header_hash(txn, header1_hash.bytes, 1);
    db::write_canonical_header(txn, header1);
    db::write_header(txn, header1, true);

    context.commit_txn();

    // for test
    Block block1;
    block1.header = header1;
    // Note: block1 has zero transactions and zero ommers on mainnet

    // prepare BodySequence
    Db::ReadWriteAccess dba(context.env());

    BlockNum highest_header = 0;
    BlockNum highest_body = 0;

    BodySequence_ForTest bs(dba, chain_identity);
    bs.sync_current_state(highest_body, highest_header);

    time_point_t tp = std::chrono::system_clock::now();
    seconds_t timeout = 1min;
    uint64_t active_peers = 1;

    SECTION("should request block 1 & should accept it") {

        // check status
        REQUIRE(bs.highest_block_in_db() == highest_body);
        REQUIRE(bs.target_height() == highest_header);
        REQUIRE(bs.highest_block_in_memory() == 0);
        REQUIRE(bs.lowest_block_in_memory() == 0);

        // requesting
        auto [packet, penalizations, min_block] = bs.request_more_bodies(tp, timeout, active_peers);

        REQUIRE(penalizations.empty());
        REQUIRE(min_block > 0);
        REQUIRE(packet.requestId != 0);  // packet = GetBlockBodiesPacket66

        std::vector<Hash>& block_requested = packet.request;
        REQUIRE(!block_requested.empty());
        REQUIRE(bs.outstanding_bodies(tp, timeout) > 0);

        REQUIRE(block_requested[0] == header1_hash);

        BodySequence_ForTest::PendingBodyRequest& request_status = bs.body_requests_[1];

        REQUIRE(request_status.block_height == 1);
        REQUIRE(request_status.block_hash == header1_hash);
        REQUIRE(request_status.header == header1);
        REQUIRE(request_status.request_time == tp);
        REQUIRE(request_status.ready == false);

        REQUIRE(bs.highest_block_in_memory() == 1);
        REQUIRE(bs.lowest_block_in_memory() == 1);

        // accepting
        PeerId peer_id{"1"};
        BlockBodiesPacket66 response_packet;
        response_packet.requestId = packet.requestId;
        response_packet.request.push_back(block1);

        auto penalty = bs.accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == NoPenalty);
        REQUIRE(request_status.ready);
        REQUIRE(request_status.body == block1);
        REQUIRE(request_status.block_height == 1); // same as before
        REQUIRE(request_status.block_hash == header1_hash); // same as before
        REQUIRE(request_status.header == header1); // same as before

        REQUIRE(bs.highest_block_in_memory() == 1); // same as before
        REQUIRE(bs.lowest_block_in_memory() == 1); // same as before

        // check statistics
        auto& statistic = bs.statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 1);
        REQUIRE(statistic.accepted_items == 1);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("should renew the request of block 1") {
        // requesting
        auto [packet1, penalizations1, min_block1] = bs.request_more_bodies(tp, timeout, active_peers);

        BodySequence_ForTest::PendingBodyRequest& request_status1 = bs.body_requests_[1];

        REQUIRE(request_status1.block_height == 1);
        REQUIRE(request_status1.request_time == tp);
        REQUIRE(request_status1.ready == false);

        request_status1.request_time -= timeout; // make request stale

        // make another request
        auto [packet2, penalizations2, min_block2] = bs.request_more_bodies(tp, timeout, active_peers);

        BodySequence_ForTest::PendingBodyRequest& request_status2 = bs.body_requests_[1];

        // should renew the previous request
        REQUIRE(request_status2.block_height == 1);
        REQUIRE(request_status2.request_time == tp);
        REQUIRE(request_status2.ready == false);

        REQUIRE(bs.highest_block_in_memory() == 1);
        REQUIRE(bs.lowest_block_in_memory() == 1);

        // check statistics
        auto& statistic = bs.statistics();
        REQUIRE(statistic.requested_items == 2);
        REQUIRE(statistic.received_items == 0);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("should ignore response with non requested bodies") {
        // requesting
        auto [packet, penalizations, min_block] = bs.request_more_bodies(tp, timeout, active_peers);

        BodySequence_ForTest::PendingBodyRequest& request_status = bs.body_requests_[1];

        REQUIRE(request_status.block_height == 1);

        // accepting
        Block block1tampered = block1;
        block1tampered.transactions.resize(1);
        block1tampered.transactions[0].nonce = 172339;
        block1tampered.transactions[0].gas_limit = 90'000;
        block1tampered.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;

        PeerId peer_id{"1"};
        BlockBodiesPacket66 response_packet;
        response_packet.requestId = packet.requestId; // correct request-id
        response_packet.request.push_back(block1tampered); // wrong body

        auto penalty = bs.accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == BadBlockPenalty);
        REQUIRE(!request_status.ready);
        REQUIRE(request_status.block_height == 1); // same as before
        REQUIRE(request_status.block_hash == header1_hash); // same as before
        REQUIRE(request_status.header == header1); // same as before

        REQUIRE(bs.highest_block_in_memory() == 1); // same as before
        REQUIRE(bs.lowest_block_in_memory() == 1); // same as before

        auto& statistic = bs.statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 1);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 1);
        REQUIRE(statistic.reject_causes.not_requested == 1);
    }

    SECTION("should ignore response with already received bodies") {
        // requesting
        auto [packet, penalizations, min_block] = bs.request_more_bodies(tp, timeout, active_peers);

        BodySequence_ForTest::PendingBodyRequest& request_status = bs.body_requests_[1];

        REQUIRE(request_status.block_height == 1);

        // accepting
        PeerId peer_id{"1"};
        BlockBodiesPacket66 response_packet;
        response_packet.requestId = packet.requestId;
        response_packet.request.push_back(block1);

        bs.accept_requested_bodies(response_packet, peer_id);

        // another one
        auto penalty = bs.accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == NoPenalty); // correct?
        REQUIRE(request_status.ready); // same as before
        REQUIRE(request_status.block_height == 1); // same as before
        REQUIRE(request_status.block_hash == header1_hash); // same as before
        REQUIRE(request_status.header == header1); // same as before

        REQUIRE(bs.highest_block_in_memory() == 1); // same as before
        REQUIRE(bs.lowest_block_in_memory() == 1); // same as before

        auto& statistic = bs.statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 2);
        REQUIRE(statistic.accepted_items == 1);
        REQUIRE(statistic.rejected_items() == 1);
        REQUIRE(statistic.reject_causes.duplicated == 1);
    }

    SECTION("should accept response with wrong request id (slow peer, request renewed)") {
        // requesting
        auto [packet, penalizations, min_block] = bs.request_more_bodies(tp, timeout, active_peers);

        BodySequence_ForTest::PendingBodyRequest& request_status = bs.body_requests_[1];

        REQUIRE(request_status.block_height == 1);

        // in real life the request can become stale and can be renewed
        // but if the peer is slow we will get a response to the old request

        PeerId peer_id{"1"};
        BlockBodiesPacket66 response_packet;
        response_packet.requestId = packet.requestId-1; // simulate response to prev request
        response_packet.request.push_back(block1);

        auto penalty = bs.accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == NoPenalty);
        REQUIRE(request_status.ready); // accepted
        REQUIRE(request_status.block_height == 1);
        REQUIRE(request_status.block_hash == header1_hash);
        REQUIRE(request_status.header == header1);

        REQUIRE(bs.highest_block_in_memory() == 1);
        REQUIRE(bs.lowest_block_in_memory() == 1);

        auto& statistic = bs.statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 1);
        REQUIRE(statistic.accepted_items == 1);
        REQUIRE(statistic.rejected_items() == 0);
        REQUIRE(statistic.reject_causes.not_requested == 0);
    }
}

}  // namespace silkworm