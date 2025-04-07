// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "remote_backend.hpp"

#include <string>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/interfaces/remote/ethbackend_mock.grpc.pb.h>
#include <silkworm/rpc/test_util/api_test_base.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address;

::types::H160* make_h160(uint64_t hi_hi, uint64_t hi_lo, uint32_t lo) {
    auto h128_ptr{new ::types::H128()};
    h128_ptr->set_hi(hi_hi);
    h128_ptr->set_lo(hi_lo);
    auto h160_ptr{new ::types::H160()};
    h160_ptr->set_allocated_hi(h128_ptr);
    h160_ptr->set_lo(lo);
    return h160_ptr;
}

::types::H256* make_h256(uint64_t hi_hi, uint64_t hi_lo, uint64_t lo_hi, uint64_t lo_lo) {
    auto h256_ptr{new ::types::H256()};
    auto hi_ptr{new ::types::H128()};
    hi_ptr->set_hi(hi_hi);
    hi_ptr->set_lo(hi_lo);
    auto lo_ptr{new ::types::H128()};
    lo_ptr->set_hi(lo_hi);
    lo_ptr->set_lo(lo_lo);
    h256_ptr->set_allocated_hi(hi_ptr);
    h256_ptr->set_allocated_lo(lo_ptr);
    return h256_ptr;
}

using StrictMockEthBackendStub = testing::StrictMock<::remote::MockETHBACKENDStub>;

using EthBackendTest = test_util::GrpcApiTestBase<ethbackend::RemoteBackEnd, StrictMockEthBackendStub>;

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(EthBackendTest, "BackEnd::etherbase", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::EtherbaseReply> reader;
    EXPECT_CALL(*stub_, AsyncEtherbaseRaw).WillOnce(testing::Return(&reader));

    SECTION("call etherbase and get address") {
        ::remote::EtherbaseReply response;
        response.set_allocated_address(make_h160(0xAAAAEEFFFFEEAAAA, 0x11DDBBAAAABBDD11, 0xCCDDDDCC));
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto etherbase = run<&ethbackend::RemoteBackEnd::etherbase>();
        CHECK(etherbase == 0xaaaaeeffffeeaaaa11ddbbaaaabbdd11ccddddcc_address);
    }

    SECTION("call etherbase and get empty address") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto etherbase = run<&ethbackend::RemoteBackEnd::etherbase>();
        CHECK(etherbase == evmc::address{});
    }

    SECTION("call etherbase and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::etherbase>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::protocol_version", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::ProtocolVersionReply> reader;
    EXPECT_CALL(*stub_, AsyncProtocolVersionRaw).WillOnce(testing::Return(&reader));

    SECTION("call protocol_version and get version") {
        ::remote::ProtocolVersionReply response;
        response.set_id(15);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto protocol_version = run<&ethbackend::RemoteBackEnd::protocol_version>();
        CHECK(protocol_version == 15);
    }

    SECTION("call protocol_version and get empty version") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto protocol_version = run<&ethbackend::RemoteBackEnd::protocol_version>();
        CHECK(protocol_version == 0);
    }

    SECTION("call protocol_version and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::protocol_version>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::net_version", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::NetVersionReply> reader;
    EXPECT_CALL(*stub_, AsyncNetVersionRaw).WillOnce(testing::Return(&reader));

    SECTION("call net_version and get version") {
        ::remote::NetVersionReply response;
        response.set_id(66);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto net_version = run<&ethbackend::RemoteBackEnd::net_version>();
        CHECK(net_version == 66);
    }

    SECTION("call net_version and get empty version") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto net_version = run<&ethbackend::RemoteBackEnd::net_version>();
        CHECK(net_version == 0);
    }

    SECTION("call net_version and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::net_version>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::client_version", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::ClientVersionReply> reader;
    EXPECT_CALL(*stub_, AsyncClientVersionRaw).WillOnce(testing::Return(&reader));

    SECTION("call client_version and get version") {
        ::remote::ClientVersionReply response;
        response.set_node_name("erigon");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto client_version = run<&ethbackend::RemoteBackEnd::client_version>();
        CHECK(client_version == "erigon");
    }

    SECTION("call client_version and get empty version") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto client_version = run<&ethbackend::RemoteBackEnd::client_version>();
        CHECK(client_version.empty());
    }

    SECTION("call client_version and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::client_version>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::get_block_num_from_txn_hash", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::TxnLookupReply> reader;
    const Hash hash;
    EXPECT_CALL(*stub_, AsyncTxnLookupRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_block_num_from_txn_hash and get number") {
        ::remote::TxnLookupReply response;
        response.set_block_number(5);
        response.set_tx_number(10000001);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto result = run<&ethbackend::RemoteBackEnd::get_block_num_from_txn_hash>(hash.bytes);
        CHECK(result->first == 5);
        CHECK(result->second == 10000001);
    }

    SECTION("call get_block_num_from_txn_hash and get zero count") {
        ::remote::TxnLookupReply response;
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        response.set_block_number(0);
        response.set_tx_number(0);
        const auto result = run<&ethbackend::RemoteBackEnd::get_block_num_from_txn_hash>(hash.bytes);
        CHECK(result == std::nullopt);
    }

    SECTION("call get_block_num_from_txn_hash and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::get_block_num_from_txn_hash>(hash.bytes)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::get_block_num_from_hash", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::HeaderNumberReply> reader;
    const Hash hash;
    EXPECT_CALL(*stub_, AsyncHeaderNumberRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_block_num_from_hash and get number") {
        ::remote::HeaderNumberReply response;
        response.set_number(3);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto block_num = run<&ethbackend::RemoteBackEnd::get_block_num_from_hash>(hash.bytes);
        CHECK(*block_num == 3);
    }

    SECTION("call get_block_num_from_hash return no number") {
        ::remote::HeaderNumberReply response;
        response.clear_number();
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto block_num = run<&ethbackend::RemoteBackEnd::get_block_num_from_hash>(hash.bytes);
        CHECK(block_num == std::nullopt);
    }
    SECTION("call get_block_num_from_hash and get zero count") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto block_num = run<&ethbackend::RemoteBackEnd::get_block_num_from_hash>(hash.bytes);
        CHECK(block_num == std::nullopt);
    }

    SECTION("call get_block_num_from_hash and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::get_block_num_from_hash>(hash.bytes)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::canonical_body_for_storage", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::CanonicalBodyForStorageReply> reader;
    const uint64_t block_num{0};
    EXPECT_CALL(*stub_, AsyncCanonicalBodyForStorageRaw).WillOnce(testing::Return(&reader));

    SECTION("call canonical_body_for_storage, and number") {
        ::remote::CanonicalBodyForStorageReply response;
        response.set_body("123");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto body = run<&ethbackend::RemoteBackEnd::canonical_body_for_storage>(block_num);
        CHECK(body == string_to_bytes("123"));
    }

    SECTION("call get_block_num_from_hash and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::canonical_body_for_storage>(block_num)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::get_block_hash_from_block_num", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::CanonicalHashReply> reader;
    const uint64_t block_num{0};
    EXPECT_CALL(*stub_, AsyncCanonicalHashRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_block_hash_from_block_num and get number") {
        ::remote::CanonicalHashReply response;
        response.set_allocated_hash(make_h256(0x3b8fb240d288781d, 0x4aac94d3fd16809e, 0xe413bc99294a0857, 0x98a589dae51ddd4a));
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto hash = run<&ethbackend::RemoteBackEnd::get_block_hash_from_block_num>(block_num);
        CHECK(hash == 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32);
    }

    SECTION("call get_block_hash_from_block_num and get zero count") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto hash = run<&ethbackend::RemoteBackEnd::get_block_hash_from_block_num>(block_num);
        CHECK(hash == std::nullopt);
    }

    SECTION("call get_block_hash_from_block_num and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::get_block_hash_from_block_num>(block_num)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::net_peer_count", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::NetPeerCountReply> reader;
    EXPECT_CALL(*stub_, AsyncNetPeerCountRaw).WillOnce(testing::Return(&reader));

    SECTION("call net_peer_count and get count") {
        ::remote::NetPeerCountReply response;
        response.set_count(20);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto net_peer_count = run<&ethbackend::RemoteBackEnd::net_peer_count>();
        CHECK(net_peer_count == 20);
    }

    SECTION("call net_peer_count and get zero count") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto net_peer_count = run<&ethbackend::RemoteBackEnd::net_peer_count>();
        CHECK(net_peer_count == 0);
    }

    SECTION("call net_peer_count and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::net_peer_count>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::node_info", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::NodesInfoReply> reader;
    EXPECT_CALL(*stub_, AsyncNodeInfoRaw).WillOnce(testing::Return(&reader));

    SECTION("call node_info") {
        ::remote::NodesInfoReply response;
        types::NodeInfoPorts ports;
        auto reply = response.add_nodes_info();
        const auto ports_ref = ports.New();
        reply->set_id("340e3cda481a935658b86f4987d50d0153a68f97fa2b9e8f70a8e9f5b755eeb6");
        reply->set_name("erigon/v2.32.0-stable-021891a3/linux-amd64/go1.19");
        reply->set_enode("enode://b428a8d89b621a1bea008922f5fb7cd7644e2289f85fc8620f1e497eff767e2bcdc77");
        reply->set_enr("enr:-JK4QJMWPkW7iDLYfevZj80Rcs-B9GkRqptsH0L6hcFKSFJ3bKFlbzjnMk29y0ZD0omRMVDlrzgTThXYcd_");
        reply->set_listener_addr("[::]:30303");
        ports_ref->set_discovery(32);
        ports_ref->set_listener(30000);
        reply->set_allocated_ports(ports_ref);
        std::string protocols = std::string(R"({"eth": {"network":5, "difficulty":10790000, "genesis":"0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a",)");
        protocols += R"("config": {"ChainName":"goerli", "chainId":5, "consensus":"clique", "homesteadBlock":0, "daoForkSupport":true, "eip150Block":0,)";
        protocols += R"("eip150Hash":"0x0000000000000000000000000000000000000000000000000000000000000000", "eip155Block":0, "byzantiumBlock":0, "constantinopleBlock":0,)";
        protocols += R"("petersburgBlock":0, "istanbulBlock":1561651, "berlinBlock":4460644, "londonBlock":5062605, "terminalTotalDifficulty":10790000,)";
        protocols += R"("terminalTotalDifficultyPassed":true, "clique": {"period":15, "epoch":30000}},)";
        protocols += R"("head":"0x11fce21bdebbcf09e1e2e37b874729c17518cd342fcf0959659e650fa45f9768"}})";
        reply->set_protocols(protocols);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto node_info = run<&ethbackend::RemoteBackEnd::engine_node_info>();
        CHECK(node_info[0].id == "340e3cda481a935658b86f4987d50d0153a68f97fa2b9e8f70a8e9f5b755eeb6");
        CHECK(node_info[0].name == "erigon/v2.32.0-stable-021891a3/linux-amd64/go1.19");
        CHECK(node_info[0].enode == "enode://b428a8d89b621a1bea008922f5fb7cd7644e2289f85fc8620f1e497eff767e2bcdc77");
        CHECK(node_info[0].enr == "enr:-JK4QJMWPkW7iDLYfevZj80Rcs-B9GkRqptsH0L6hcFKSFJ3bKFlbzjnMk29y0ZD0omRMVDlrzgTThXYcd_");
        CHECK(node_info[0].listener_addr == "[::]:30303");
        CHECK(node_info[0].protocols == protocols);
        CHECK(node_info[0].ports.discovery == 32);
        CHECK(node_info[0].ports.listener == 30000);
    }
}

// TODO(canepat) move these unit tests to execute.proto I/F implementation
/*TEST_CASE_METHOD(EthBackendTest, "BackEnd::engine_get_payload", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::EngineGetPayloadResponse> reader;
    EXPECT_CALL(*stub_, AsyncEngineGetPayloadRaw).WillOnce(testing::Return(&reader));

    SECTION("call engine_get_payload and get payload") {
        const auto p{new ::types::ExecutionPayload};
        p->set_allocated_coinbase(make_h160(0xa94f5374fce5edbc, 0x8e2a8697c1533167, 0x7e6ebf0b));
        p->set_allocated_block_hash(make_h256(0x3559e851470f6e7b, 0xbed1db474980683e, 0x8c315bfce99b2a6e, 0xf47c057c04de7858));
        p->set_allocated_base_fee_per_gas(make_h256(0x0, 0x0, 0x0, 0x7));
        p->set_allocated_state_root(make_h256(0xca3149fa9e37db08, 0xd1cd49c9061db100, 0x2ef1cd58db2210f2, 0x115c8c989b2bdf45));
        p->set_allocated_receipt_root(make_h256(0x56e81f171bcc55a6, 0xff8345e692c0f86e, 0x5b48e01b996cadc0, 0x01622fb5e363b421));
        p->set_allocated_parent_hash(make_h256(0x3b8fb240d288781d, 0x4aac94d3fd16809e, 0xe413bc99294a0857, 0x98a589dae51ddd4a));
        p->set_allocated_prev_randao(make_h256(0x0, 0x0, 0x0, 0x1));
        p->set_block_num(0x1);
        p->set_gas_limit(0x1c9c380);
        p->set_timestamp(0x5);
        const Bytes tx_bytes{*from_hex("0xf92ebdeab45d368f6354e8c5a8ac586c")};
        p->add_transactions(tx_bytes.data(), tx_bytes.size());
        const auto hi_hi_hi_logsbloom{make_h256(0x1000000000000000, 0x0, 0x0, 0x0)};
        const auto hi_hi_logsbloom{new ::types::H512()};
        hi_hi_logsbloom->set_allocated_hi(hi_hi_hi_logsbloom);
        const auto hi_logsbloom{new ::types::H1024()};
        hi_logsbloom->set_allocated_hi(hi_hi_logsbloom);
        const auto logsbloom{new ::types::H2048()};
        logsbloom->set_allocated_hi(hi_logsbloom);
        p->set_allocated_logs_bloom(logsbloom);

        ::remote::EngineGetPayloadResponse response;
        response.set_allocated_execution_payload(p);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));

        const auto payload_and_value = run<&ethbackend::RemoteBackEnd::engine_get_payload>(0u);
        const auto& payload = payload_and_value.payload;
        CHECK(payload.number == 0x1);
        CHECK(payload.gas_limit == 0x1c9c380);
        CHECK(payload.suggested_fee_recipient == 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address);
        CHECK(payload.state_root == 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45_bytes32);
        CHECK(payload.receipts_root == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32);
        CHECK(payload.parent_hash == 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32);
        CHECK(payload.block_hash == 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32);
        CHECK(payload.prev_randao == 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32);
        CHECK(payload.base_fee == 0x7);
        CHECK(payload.transactions.size() == 1);
        CHECK(to_hex(payload.transactions[0]) == "f92ebdeab45d368f6354e8c5a8ac586c");
        silkworm::Bloom expected_bloom{0};
        expected_bloom[0] = 0x10;
        CHECK(payload.logs_bloom == expected_bloom);
        CHECK(payload_and_value.block_value == 0);
    }

    SECTION("call engine_get_payload and get empty payload") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto payload = run<&ethbackend::RemoteBackEnd::engine_get_payload>(0u);
        CHECK(payload.payload.number == 0);
    }

    SECTION("call engine_get_payload and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::engine_get_payload>(0u)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::engine_new_payload", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::EnginePayloadStatus> reader;
    EXPECT_CALL(*stub_, AsyncEngineNewPayloadRaw).WillOnce(testing::Return(&reader));

    silkworm::Bloom bloom;
    bloom.fill(0);
    bloom[0] = 0x12;
    const Bytes transaction{*from_hex("0xf92ebdeab45d368f6354e8c5a8ac586c")};
    const NewPayloadRequest request_v1{
        .execution_payload = ExecutionPayload{
            .version = ExecutionPayload::kV1,
            .timestamp = 0x5,
            .gas_limit = 0x1c9c380,
            .gas_used = 0x9,
            .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
            .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf43_bytes32,
            .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
            .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
            .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
            .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
            .base_fee = 0x7,
            .logs_bloom = bloom,
            .transactions = {transaction},
        },
    };
    const NewPayloadRequest request_v2_no_w{
        .execution_payload = ExecutionPayload{
            .version = ExecutionPayload::kV2,
            .timestamp = 0x5,
            .gas_limit = 0x1c9c380,
            .gas_used = 0x9,
            .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
            .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf43_bytes32,
            .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
            .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
            .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
            .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
            .base_fee = 0x7,
            .logs_bloom = bloom,
            .transactions = {transaction},
            .withdrawals = std::vector<Withdrawal>{},
        },
    };
    const NewPayloadRequest request_v2_w{
        .execution_payload = ExecutionPayload{
            .version = ExecutionPayload::kV2,
            .timestamp = 0x5,
            .gas_limit = 0x1c9c380,
            .gas_used = 0x9,
            .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
            .state_root = 0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf43_bytes32,
            .receipts_root = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32,
            .parent_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
            .block_hash = 0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858_bytes32,
            .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
            .base_fee = 0x7,
            .logs_bloom = bloom,
            .transactions = {transaction},
            .withdrawals = std::vector<Withdrawal>{
                {.index = 6, .validator_index = 12, .address = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address, .amount = 10'000}},
        },
    };
    const std::vector<NewPayloadRequest> requests = {request_v1, request_v2_no_w, request_v2_w};
    for (size_t i{0}; i < requests.size(); ++i) {
        const auto& new_payload_request = requests[i];

        SECTION("call engine_new_payload and get VALID status [i=" + std::to_string(i) + "]") {
            ::remote::EnginePayloadStatus response;
            response.set_allocated_latest_valid_hash(make_h256(0, 0, 0, 0x40));
            response.set_status(::remote::EngineStatus::VALID);
            response.set_validation_error("some error");
            EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
            const auto payload_status = run<&ethbackend::RemoteBackEnd::engine_new_payload>(new_payload_request);
            CHECK(payload_status.status == "VALID");
            CHECK(payload_status.latest_valid_hash == 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32);
            CHECK(payload_status.validation_error == "some error");
        }

        const ::remote::EngineStatus all_engine_statuses[] = {
            ::remote::EngineStatus::VALID,
            ::remote::EngineStatus::INVALID,
            ::remote::EngineStatus::SYNCING,
            ::remote::EngineStatus::ACCEPTED,
            ::remote::EngineStatus::INVALID_BLOCK_HASH};
        for (const auto engine_status : all_engine_statuses) {
            const auto engine_status_name{::remote::EngineStatus_Name(engine_status)};
            SECTION(std::string("call engine_new_payload and get ") + engine_status_name + " status [i=" + std::to_string(i) + "]") {
                ::remote::EnginePayloadStatus response;
                response.set_status(engine_status);
                EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
                const auto payload_status = run<&ethbackend::RemoteBackEnd::engine_new_payload>(new_payload_request);
                CHECK(payload_status.status == engine_status_name);
            }
        }

        SECTION("call engine_new_payload and get empty payload [i=" + std::to_string(i) + "]") {
            EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
            const auto payload_status = run<&ethbackend::RemoteBackEnd::engine_new_payload>(new_payload_request);
            CHECK(payload_status.status == "VALID");  // Default value in interfaces is Valid
            CHECK(payload_status.latest_valid_hash == std::nullopt);
            CHECK(payload_status.validation_error == std::nullopt);
        }

        SECTION("call engine_new_payload and get error [i=" + std::to_string(i) + "]") {
            EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
            CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::engine_new_payload>(new_payload_request)), rpc::GrpcStatusError);
        }
    }
}

TEST_CASE_METHOD(EthBackendTest, "BackEnd::engine_forkchoice_updated", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::EngineForkChoiceUpdatedResponse> reader;
    EXPECT_CALL(*stub_, AsyncEngineForkChoiceUpdatedRaw).WillOnce(testing::Return(&reader));

    const ForkChoiceUpdatedRequest forkchoice_request{
        .fork_choice_state =
            ForkChoiceState{
                .head_block_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
                .safe_block_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32,
                .finalized_block_hash = 0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a_bytes32},
        .payload_attributes =
            PayloadAttributes{
                .timestamp = 0x1,
                .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
                .suggested_fee_recipient = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address}};
    SECTION("call engine_forkchoice_updated_v1 and get VALID status") {
        ::remote::EngineForkChoiceUpdatedResponse response;
        auto* engine_payload_status = new ::remote::EnginePayloadStatus();
        engine_payload_status->set_allocated_latest_valid_hash(make_h256(0, 0, 0, 0x40));
        engine_payload_status->set_validation_error("some error");
        engine_payload_status->set_status(::remote::EngineStatus::VALID);
        response.set_allocated_payload_status(engine_payload_status);
        response.set_payload_id(1);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto forkchoice_reply = run<&ethbackend::RemoteBackEnd::engine_forkchoice_updated>(forkchoice_request);
        const PayloadStatus payload_status = forkchoice_reply.payload_status;
        CHECK(payload_status.status == "VALID");
        CHECK(payload_status.latest_valid_hash == 0x0000000000000000000000000000000000000000000000000000000000000040_bytes32);
        CHECK(payload_status.validation_error == "some error");
    }

    SECTION("call engine_forkchoice_updated_v1 and get zero count") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto forkchoice_reply = run<&ethbackend::RemoteBackEnd::engine_forkchoice_updated>(forkchoice_request);
        const PayloadStatus payload_status = forkchoice_reply.payload_status;
        CHECK(payload_status.status == "VALID");  // Default value in interfaces is Valid
        CHECK(payload_status.latest_valid_hash == std::nullopt);
        CHECK(payload_status.validation_error == std::nullopt);
    }

    SECTION("call engine_forkchoice_updated_v1 and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&ethbackend::RemoteBackEnd::engine_forkchoice_updated>(forkchoice_request)), rpc::GrpcStatusError);
    }
}*/

TEST_CASE_METHOD(EthBackendTest, "BackEnd::peers", "[silkworm][rpc][ethbackend][backend]") {
    test::StrictMockAsyncResponseReader<::remote::PeersReply> reader;
    EXPECT_CALL(*stub_, AsyncPeersRaw).WillOnce(testing::Return(&reader));

    SECTION("call peers") {
        ::remote::PeersReply response;
        auto reply = response.add_peers();
        reply->set_id("340e3cda481a935658b86f4987d50d0153a68f97fa2b9e8f70a8e9f5b755eeb6");
        reply->set_name("erigon/v2.32.0-stable-021891a3/linux-amd64/go1.19");
        reply->set_enode("enode://b428a8d89b621a1bea008922f5fb7cd7644e2289f85fc8620f1e497eff767e2bcdc77");
        reply->set_enr("enr:-JK4QJMWPkW7iDLYfevZj80Rcs-B9GkRqptsH0L6hcFKSFJ3bKFlbzjnMk29y0ZD0omRMVDlrzgTThXYcd_");
        reply->set_conn_local_addr("[::]:30303");
        reply->set_conn_remote_addr("[::]:30302");
        reply->set_conn_is_inbound(false);
        reply->set_conn_is_trusted(true);
        reply->set_conn_is_static(true);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto peer_infos = run<&ethbackend::RemoteBackEnd::peers>();
        CHECK(peer_infos.size() == 1);
        const auto& peer_info = peer_infos[0];
        CHECK(peer_info.id == "340e3cda481a935658b86f4987d50d0153a68f97fa2b9e8f70a8e9f5b755eeb6");
        CHECK(peer_info.name == "erigon/v2.32.0-stable-021891a3/linux-amd64/go1.19");
        CHECK(peer_info.enode == "enode://b428a8d89b621a1bea008922f5fb7cd7644e2289f85fc8620f1e497eff767e2bcdc77");
        CHECK(peer_info.enr == "enr:-JK4QJMWPkW7iDLYfevZj80Rcs-B9GkRqptsH0L6hcFKSFJ3bKFlbzjnMk29y0ZD0omRMVDlrzgTThXYcd_");
        CHECK(peer_info.caps.empty());
        CHECK(peer_info.local_address == "[::]:30303");
        CHECK(peer_info.remote_address == "[::]:30302");
        CHECK(!peer_info.is_connection_inbound);
        CHECK(peer_info.is_connection_trusted);
        CHECK(peer_info.is_connection_static);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
