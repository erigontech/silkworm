// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "body_sequence.hpp"

#include <algorithm>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/sync/sentry_client.hpp>

namespace silkworm {
// Useful definitions
// ----------------------------------------------------------------------------

class BodySequenceForTest : public BodySequence {
  public:
    // inheriting constructor
    using BodySequence::BodySequence;
    // publication of internal members to test methods functioning
    using BodySequence::announced_blocks_;
    using BodySequence::body_requests_;
    using BodySequence::BodyRequest;
};

TEST_CASE_METHOD(BodySequenceForTest, "body downloading", "[sync][internals]") {
    using namespace std;
    using namespace std::chrono_literals;
    using intx::operator""_u256;

    db::test_util::TempChainData context;
    context.add_genesis_data();

    auto& txn{context.rw_txn()};

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

    BlockNum max_header = 1;

    current_state(0);
    download_bodies({make_shared<BlockHeader>(header1)});

    time_point_t tp = std::chrono::system_clock::now();
    seconds_t request_timeout = SentryClient::kRequestDeadline;

    SECTION("should request block 1 & should accept it") {
        // check status
        REQUIRE(max_block_in_output() == 0);
        REQUIRE(target_block_num() == max_header);
        REQUIRE(max_block_in_memory() == max_header);
        REQUIRE(lowest_block_in_memory() == max_header);

        // requesting
        std::shared_ptr<OutboundMessage> message = request_bodies(tp);
        REQUIRE(message != nullptr);

        auto get_bodies_msg = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message);
        REQUIRE(get_bodies_msg != nullptr);

        CHECK(get_bodies_msg->packet_present());
        auto penalizations = get_bodies_msg->penalties();
        CHECK(penalizations.empty());

        CHECK(get_bodies_msg->penalties().empty());
        CHECK(get_bodies_msg->min_block() > 0);
        REQUIRE(get_bodies_msg->packet_present());

        auto& packet = get_bodies_msg->packet();

        std::vector<Hash>& block_requested = packet.request;
        REQUIRE(!block_requested.empty());
        REQUIRE(outstanding_requests(tp) > 0);

        REQUIRE(block_requested[0] == header1_hash);

        REQUIRE(!body_requests_.empty());
        REQUIRE(body_requests_.lowest_block() == 1);
        REQUIRE(body_requests_.max_block() == 1);

        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        REQUIRE(request_status.block_num == 1);
        REQUIRE(request_status.block_hash == header1_hash);
        REQUIRE(request_status.header == header1);
        REQUIRE(request_status.request_time == tp);
        REQUIRE(request_status.ready == false);

        REQUIRE(max_block_in_memory() == 1);
        REQUIRE(lowest_block_in_memory() == 1);

        // accepting
        PeerId peer_id{byte_ptr_cast("1")};
        BlockBodiesPacket66 response_packet;
        response_packet.request_id = packet.request_id;
        response_packet.request.push_back(block1);

        auto penalty = accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == kNoPenalty);
        REQUIRE(request_status.ready);
        REQUIRE(request_status.body == block1);
        REQUIRE(request_status.block_num == 1);              // same as before
        REQUIRE(request_status.block_hash == header1_hash);  // same as before
        REQUIRE(request_status.header == header1);           // same as before

        REQUIRE(max_block_in_memory() == 1);     // same as before
        REQUIRE(lowest_block_in_memory() == 1);  // same as before

        // check statistics
        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 1);
        REQUIRE(statistic.accepted_items == 1);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("should renew the request of block 1") {
        // requesting
        std::shared_ptr<OutboundMessage> message1 = request_bodies(tp);

        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status1 = rs->second;

        REQUIRE(request_status1.block_num == 1);
        REQUIRE(request_status1.request_time == tp);
        REQUIRE(request_status1.ready == false);

        request_status1.request_time -= request_timeout;  // make request stale

        // make another request
        std::shared_ptr<OutboundMessage> message2 = request_bodies(tp);

        rs = body_requests_.find(1);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status2 = rs->second;

        // should renew the previous request
        REQUIRE(request_status2.block_num == 1);
        REQUIRE(request_status2.request_time == tp);
        REQUIRE(request_status2.ready == false);

        REQUIRE(max_block_in_memory() == 1);
        REQUIRE(lowest_block_in_memory() == 1);

        // check statistics
        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 2);
        REQUIRE(statistic.received_items == 0);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("should ignore response with non requested bodies") {
        // requesting
        std::shared_ptr<OutboundMessage> message = request_bodies(tp);
        REQUIRE(message != nullptr);

        auto get_bodies_msg = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message);
        REQUIRE(get_bodies_msg != nullptr);

        auto& packet = get_bodies_msg->packet();

        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        // accepting
        Block block1tampered = block1;
        block1tampered.transactions.resize(1);
        block1tampered.transactions[0].nonce = 172339;
        block1tampered.transactions[0].gas_limit = 90'000;
        block1tampered.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;

        PeerId peer_id{byte_ptr_cast("1")};
        BlockBodiesPacket66 response_packet;
        response_packet.request_id = packet.request_id;     // correct request-id
        response_packet.request.push_back(block1tampered);  // wrong body

        [[maybe_unused]] auto penalty = accept_requested_bodies(response_packet, peer_id);

        // REQUIRE(penalty == kBadBlockPenalty); // for now we choose to not penalize the peer
        REQUIRE(!request_status.ready);
        REQUIRE(request_status.block_num == 1);              // same as before
        REQUIRE(request_status.block_hash == header1_hash);  // same as before
        REQUIRE(request_status.header == header1);           // same as before

        REQUIRE(max_block_in_memory() == 1);     // same as before
        REQUIRE(lowest_block_in_memory() == 1);  // same as before

        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 1);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 1);
        REQUIRE(statistic.reject_causes.not_requested == 1);
    }

    SECTION("should ignore response with already received bodies") {
        // requesting
        std::shared_ptr<OutboundMessage> message = request_bodies(tp);
        REQUIRE(message != nullptr);

        auto get_bodies_msg = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message);
        REQUIRE(get_bodies_msg != nullptr);

        auto& packet = get_bodies_msg->packet();

        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        // accepting
        PeerId peer_id{byte_ptr_cast("1")};
        BlockBodiesPacket66 response_packet;
        response_packet.request_id = packet.request_id;
        response_packet.request.push_back(block1);

        accept_requested_bodies(response_packet, peer_id);

        // another one
        auto penalty = accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == kNoPenalty);                      // correct?
        REQUIRE(request_status.ready);                       // same as before
        REQUIRE(request_status.block_num == 1);              // same as before
        REQUIRE(request_status.block_hash == header1_hash);  // same as before
        REQUIRE(request_status.header == header1);           // same as before

        REQUIRE(max_block_in_memory() == 1);     // same as before
        REQUIRE(lowest_block_in_memory() == 1);  // same as before

        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 2);
        REQUIRE(statistic.accepted_items == 1);
        REQUIRE(statistic.rejected_items() == 1);
        REQUIRE(statistic.reject_causes.duplicated == 1);
    }

    SECTION("should accept response with wrong request id (slow peer, request renewed)") {
        // requesting
        std::shared_ptr<OutboundMessage> message = request_bodies(tp);
        REQUIRE(message != nullptr);

        auto get_bodies_msg = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message);
        REQUIRE(get_bodies_msg != nullptr);

        auto& packet = get_bodies_msg->packet();

        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        // in real life the request can become stale and can be renewed
        // but if the peer is slow we will get a response to the old request

        PeerId peer_id{byte_ptr_cast("1")};
        BlockBodiesPacket66 response_packet;
        response_packet.request_id = packet.request_id - 1;  // simulate response to prev request
        response_packet.request.push_back(block1);

        auto penalty = accept_requested_bodies(response_packet, peer_id);

        REQUIRE(penalty == kNoPenalty);
        REQUIRE(request_status.ready);  // accepted
        REQUIRE(request_status.block_num == 1);
        REQUIRE(request_status.block_hash == header1_hash);
        REQUIRE(request_status.header == header1);

        REQUIRE(max_block_in_memory() == 1);
        REQUIRE(lowest_block_in_memory() == 1);

        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 1);
        REQUIRE(statistic.accepted_items == 1);
        REQUIRE(statistic.rejected_items() == 0);
        REQUIRE(statistic.reject_causes.not_requested == 0);
    }

    SECTION("should not renew recent requests") {
        REQUIRE(max_header == 1);  // test pre-requisite

        // requesting
        std::shared_ptr<OutboundMessage> message1 = request_bodies(tp);

        REQUIRE(body_requests_.size() == 1);

        // make another request in the same time
        std::shared_ptr<OutboundMessage> message2 = request_bodies(tp);
        REQUIRE(message2 != nullptr);

        auto get_bodies_msg2 = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message2);
        REQUIRE(get_bodies_msg2 != nullptr);

        auto& packet2 = get_bodies_msg2->packet();

        REQUIRE(packet2.request.empty());  // no new request, max_header == 1, and we already requested body 1
        REQUIRE(body_requests_.size() == 1);

        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        REQUIRE(request_status.block_num == 1);
        REQUIRE(request_status.request_time == tp);
        REQUIRE(request_status.ready == false);

        // statistics
        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 1);
        REQUIRE(statistic.received_items == 0);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("should not make other requests after a nack") {
        REQUIRE(max_header == 1);  // test pre-requisite

        // requesting
        std::shared_ptr<OutboundMessage> message1 = request_bodies(tp);
        REQUIRE(message1 != nullptr);

        auto get_bodies_msg1 = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message1);
        REQUIRE(get_bodies_msg1 != nullptr);

        auto& packet1 = get_bodies_msg1->packet();

        REQUIRE(body_requests_.size() == 1);
        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        auto& statistic = statistics();

        REQUIRE(request_status.block_num == 1);
        REQUIRE(request_status.request_time == tp);
        REQUIRE(request_status.ready == false);
        REQUIRE(statistic.requested_items == 1);

        // submit nack
        request_nack(packet1);

        REQUIRE(statistic.requested_items == 0);  // reset

        // make another request in the same time
        std::shared_ptr<OutboundMessage> message2 = request_bodies(tp);
        REQUIRE(message2 == nullptr);  // no new request, last was a nack

        REQUIRE(body_requests_.size() == 1);

        // statistics
        REQUIRE(statistic.requested_items == 0);
        REQUIRE(statistic.received_items == 0);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("should not renew ready requests") {
        REQUIRE(max_header == 1);  // test pre-requisite

        // requesting
        std::shared_ptr<OutboundMessage> message1 = request_bodies(tp);

        REQUIRE(body_requests_.size() == 1);
        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        request_status.ready = true;               // mark as ready
        tp += 2 * SentryClient::kRequestDeadline;  // make it stale

        // make another request in the same time
        std::shared_ptr<OutboundMessage> message2 = request_bodies(tp);
        REQUIRE(message2 != nullptr);

        auto get_bodies_msg2 = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message2);
        REQUIRE(get_bodies_msg2 != nullptr);

        auto& packet2 = get_bodies_msg2->packet();

        REQUIRE(packet2.request.empty());  // no new request, max_header == 1, and we already requested body 1
        REQUIRE(body_requests_.size() == 1);
    }

    SECTION("should not renew recent requests but make new requests") {
        // requesting
        std::shared_ptr<OutboundMessage> message1 = request_bodies(tp);

        REQUIRE(body_requests_.size() == 1);
        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status1 = rs->second;

        // make another request in the same time
        BlockHeader header2;
        header2.number = 2;
        header2.parent_hash = header1_hash;
        datastore::kvdb::RWTxnManaged txn2 = context.chaindata_rw().start_rw_tx();
        db::write_canonical_header_hash(txn2, header2.hash().bytes, 1);
        db::write_canonical_header(txn2, header2);
        db::write_header(txn2, header2, true);
        txn2.commit_and_renew();
        download_bodies({make_shared<BlockHeader>(header2)});

        std::shared_ptr<OutboundMessage> message2 = request_bodies(tp);
        REQUIRE(message2 != nullptr);

        auto get_bodies_msg2 = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message2);
        REQUIRE(get_bodies_msg2 != nullptr);

        auto& packet2 = get_bodies_msg2->packet();

        REQUIRE(!packet2.request.empty());
        REQUIRE(body_requests_.size() == 2);
        rs = body_requests_.find(header2.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status2 = rs->second;

        // should not renew the previous request
        REQUIRE(request_status2.block_num != request_status1.block_num);

        // statistics
        auto& statistic = statistics();
        REQUIRE(statistic.requested_items == 2);
        REQUIRE(statistic.received_items == 0);
        REQUIRE(statistic.accepted_items == 0);
        REQUIRE(statistic.rejected_items() == 0);
    }

    SECTION("accepting and using an announced block") {
        // accepting announcement
        PeerId peer_id{byte_ptr_cast("1")};
        accept_new_block(block1, peer_id);
        REQUIRE(announced_blocks_.size() == 1);

        // requesting block 1 and finding it in announcements
        std::shared_ptr<OutboundMessage> message = request_bodies(tp);
        REQUIRE(message != nullptr);

        auto get_bodies_msg = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message);
        REQUIRE(get_bodies_msg != nullptr);

        REQUIRE(get_bodies_msg->penalties().empty());
        REQUIRE(!get_bodies_msg->packet_present());  // no new request, we reached max_header (=1)

        REQUIRE(!body_requests_.empty());
        auto rs = body_requests_.find(header1.number);
        REQUIRE(rs != body_requests_.end());
        BodySequenceForTest::BodyRequest& request_status = rs->second;

        REQUIRE(request_status.ready == true);        // found on announcements
        REQUIRE(request_status.to_announce == true);  // to announce

        REQUIRE(announced_blocks_.size() == 0);
    }
}

TEST_CASE_METHOD(BodySequenceForTest, "reject block body with invalid withdrawals", "[sync][internals]") {
    const Bytes encoded_header_21072002 = *from_hex(
        "f90260a0e0a4eac8dd2fe1271a8a7d4eab99dfe456e97c63904c3d26d74de0bce6929d3fa01dcc4de8dec75d7aab85b567b6ccd41ad312"
        "451b948a7413f0a142fd40d4934794afedf06777839d59eed3163cc3e0a5057b514399a00cc0db0367272cf732cadbf7ff0975e06679b6"
        "d91cc45c08e5479073ea9520a2a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6"
        "ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000008084014188828401c9c38080846720f66b99d883010d0c846765746888676f312e32312e36856c696e7578a0d99996"
        "d768137199d2e7df9b78ca5523e688fdc43b3a0a9cfd2478ca243b052f8800000000000000008502fef7b251a0c18745982077dc6d0ad1"
        "93a0142a55f5239d7c4f757a6b9bfaad89fcfa02886a808404b00000a045269c7f581f0bcbdb33f1209a82545194134960c55ccb5286ff"
        "fa31219f36aa");
    ByteView encoded_header_view = encoded_header_21072002;
    BlockHeader header;
    REQUIRE(rlp::decode(encoded_header_view, header));
    REQUIRE(header.number == 21'072'002);

    const Bytes encoded_invalid_body_21072002 = *from_hex(
        "f9024a849b23ba7b02c0f90240e38403d933eb830d7ae894b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840127a3f1e38403d933ec"
        "830d7ae994b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840126fa82e38403d933ed830d7aea94b9d7934878b5fb9610b3fe8a5e44"
        "1e8fad7e293f84012650fee38403d933ee830d7aeb94b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840126192ce38403d933ef830d"
        "7aec94b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840124ce1fe38403d933f0830d7aed94b9d7934878b5fb9610b3fe8a5e441e8f"
        "ad7e293f840125293ce38403d933f1830d7aee94b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840127ac27e38403d933f2830d7aef94b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840128315ee38403d933f3830d7af094b9d7934878b5fb9610b3fe8a5e441e8fad7e293f8401280443e38403d933f4830d7af194b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840127e8bae38403d933f5830d7af294b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840126e7aee38403d933f6830d7af394b9d7934878b5fb9610b3fe8a5e441e8fad7e293f84012762d0e38403d933f7830d7af494b9d7934878b5fb9610b3fe8a5e441e8fad7e293f8401271437e38403d933f8830d7af594b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840126aa33e38403d933f9830d7af694b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840127809ae38403d933fa830d7af794b9d7934878b5fb9610b3fe8a5e441e8fad7e293f840127eb60");
    ByteView encoded_invalid_body_view = encoded_invalid_body_21072002;
    BlockBodyForStorage invalid_body;
    REQUIRE(decode_stored_block_body(encoded_invalid_body_view, invalid_body));
    REQUIRE(invalid_body.txn_count == 2);  // block 21072002 has 0 user + 2 system transactions
    REQUIRE(invalid_body.withdrawals);

    const std::vector<Withdrawal> withdrawals{*invalid_body.withdrawals};
    static constexpr auto kEncoder = [](Bytes& to, const Withdrawal& w) { rlp::encode(to, w); };
    REQUIRE(trie::root_hash(withdrawals, kEncoder) != *header.withdrawals_root);  // <- ensure reconstructed block 21072002 is INVALID

    // Setting target
    current_state(header.number - 1);
    download_bodies({std::make_shared<BlockHeader>(header)});

    const time_point_t tp = std::chrono::system_clock::now();

    // Requesting
    std::shared_ptr<OutboundMessage> message = request_bodies(tp);
    REQUIRE(message != nullptr);

    const auto get_bodies_msg = std::dynamic_pointer_cast<OutboundGetBlockBodies>(message);
    REQUIRE(get_bodies_msg != nullptr);

    const auto& packet = get_bodies_msg->packet();
    const auto rs = body_requests_.find(header.number);
    REQUIRE(rs != body_requests_.end());
    const BodySequenceForTest::BodyRequest& request_status = rs->second;

    // Accepting
    Block invalid_block;
    invalid_block.header = header;
    invalid_block.withdrawals = invalid_body.withdrawals;

    const PeerId peer_id{byte_ptr_cast("1")};
    BlockBodiesPacket66 response_packet;
    response_packet.request_id = packet.request_id;    // correct request-id
    response_packet.request.push_back(invalid_block);  // wrong body

    [[maybe_unused]] const auto penalty = accept_requested_bodies(response_packet, peer_id);

    // REQUIRE(penalty == kBadBlockPenalty); // for now we choose to not penalize the peer
    CHECK(!request_status.ready);
    CHECK(request_status.block_num == 21072002);        // same as before
    CHECK(request_status.block_hash == header.hash());  // same as before
    CHECK(request_status.header == header);             // same as before

    const auto& stats = statistics();
    CHECK(stats.requested_items == 1);
    CHECK(stats.received_items == 1);
    CHECK(stats.accepted_items == 0);
    CHECK(stats.rejected_items() == 1);
    CHECK(stats.reject_causes.not_requested == 1);
}

}  // namespace silkworm
