/*
   Copyright 2023 The Silkworm Authors

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

#include "version.hpp"

#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <catch2/catch.hpp>
#include <gmock/gmock.h>
#include <grpcpp/server_builder.h>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/interfaces/txpool/mining.grpc.pb.h>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/test/interfaces/ethbackend_mock_fix24351.grpc.pb.h>
#include <silkworm/silkrpc/test/interfaces/kv_mock_fix24351.grpc.pb.h>
#include <silkworm/silkrpc/test/interfaces/mining_mock_fix24351.grpc.pb.h>
#include <silkworm/silkrpc/test/interfaces/txpool_mock_fix24351.grpc.pb.h>

namespace silkrpc {

using Catch::Matchers::Message;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::_;

TEST_CASE("write protocol version to ostream", "[silkrpc][protocol][version]") {
    const ProtocolVersion v{1, 0, 0};
    CHECK_NOTHROW(null_stream() << v);
}

TEST_CASE("ETHBACKEND protocol version error", "[silkrpc][protocol][wait_for_ethbackend_protocol_check]") {
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockETHBACKENDStub>()};

    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockETHBACKENDStub*>(stub.get()), Version(_, _, _)).WillOnce(
        Return(grpc::Status::CANCELLED));
    const auto version_result{wait_for_ethbackend_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("ETHBACKEND protocol version major mismatch", "[silkrpc][protocol][wait_for_ethbackend_protocol_check]") {
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockETHBACKENDStub>()};
    types::VersionReply reply;

    reply.set_major(1);
    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockETHBACKENDStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result1{wait_for_ethbackend_protocol_check(stub)};
    CHECK(version_result1.compatible == false);
    CHECK(version_result1.result.find("incompatible") != std::string::npos);

    reply.set_major(3);
    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockETHBACKENDStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result2{wait_for_ethbackend_protocol_check(stub)};
    CHECK(version_result2.compatible == false);
    CHECK(version_result2.result.find("incompatible") != std::string::npos);
}

TEST_CASE("ETHBACKEND protocol version minor mismatch", "[silkrpc][protocol][wait_for_ethbackend_protocol_check]") {
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockETHBACKENDStub>()};
    types::VersionReply reply;
    reply.set_major(2);

    reply.set_minor(2);
    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockETHBACKENDStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result1{wait_for_ethbackend_protocol_check(stub)};
    CHECK(version_result1.compatible == false);
    CHECK(version_result1.result.find("incompatible") != std::string::npos);

    reply.set_minor(4);
    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockETHBACKENDStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result2{wait_for_ethbackend_protocol_check(stub)};
    CHECK(version_result2.compatible == false);
    CHECK(version_result2.result.find("incompatible") != std::string::npos);
}

TEST_CASE("ETHBACKEND protocol version match", "[silkrpc][protocol][wait_for_ethbackend_protocol_check]") {
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockETHBACKENDStub>()};
    types::VersionReply reply;
    reply.set_major(3);
    reply.set_minor(1);

    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockETHBACKENDStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_ethbackend_protocol_check(stub)};
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("ETHBACKEND protocol version with server stub", "[silkrpc][protocol][wait_for_ethbackend_protocol_check]") {
    class TestService : public ::remote::ETHBACKEND::Service {
    public:
        ::grpc::Status Version(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response) override {
            response->set_major(3);
            response->set_minor(1);
            response->set_patch(0);
            return ::grpc::Status::OK;
        }
    };
    TestService service;
    std::ostringstream server_address;
    server_address << "localhost:" << 12345; // TODO(canepat): grpc_pick_unused_port_or_die
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address.str(), grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    const auto server_ptr = builder.BuildAndStart();
    const auto channel = grpc::CreateChannel(server_address.str(), grpc::InsecureChannelCredentials());
    const auto version_result{wait_for_ethbackend_protocol_check(channel)};
    server_ptr->Shutdown();
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("KV protocol version error", "[silkrpc][protocol][wait_for_kv_protocol_check]") {
    std::unique_ptr<::remote::KV::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockKVStub>()};

    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockKVStub*>(stub.get()), Version(_, _, _)).WillOnce(
        Return(grpc::Status::CANCELLED));
    const auto version_result{wait_for_kv_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("KV protocol version major mismatch", "[silkrpc][protocol][wait_for_kv_protocol_check]") {
    std::unique_ptr<::remote::KV::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockKVStub>()};
    types::VersionReply reply;

    reply.set_major(KV_SERVICE_API_VERSION.major - 1);
    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockKVStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result1{wait_for_kv_protocol_check(stub)};
    CHECK(version_result1.compatible == false);
    CHECK(version_result1.result.find("incompatible") != std::string::npos);

    reply.set_major(KV_SERVICE_API_VERSION.major + 1);
    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockKVStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result2{wait_for_kv_protocol_check(stub)};
    CHECK(version_result2.compatible == false);
    CHECK(version_result2.result.find("incompatible") != std::string::npos);
}

TEST_CASE("KV protocol version minor mismatch", "[silkrpc][protocol][wait_for_kv_protocol_check]") {
    std::unique_ptr<::remote::KV::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockKVStub>()};
    types::VersionReply reply;
    reply.set_major(KV_SERVICE_API_VERSION.major); // Major is unchanged
    reply.set_minor(KV_SERVICE_API_VERSION.minor + 1); // Minor is different

    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockKVStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_kv_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("KV protocol version match", "[silkrpc][protocol][wait_for_kv_protocol_check]") {
    std::unique_ptr<::remote::KV::StubInterface> stub{std::make_unique<::remote::FixIssue24351_MockKVStub>()};
    types::VersionReply reply;
    reply.set_major(6);
    reply.set_minor(0);

    EXPECT_CALL(*dynamic_cast<::remote::FixIssue24351_MockKVStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_kv_protocol_check(stub)};
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("KV protocol version with server stub", "[silkrpc][protocol][wait_for_kv_protocol_check]") {
    class TestService : public ::remote::KV::Service {
    public:
        ::grpc::Status Version(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response) override {
            response->set_major(6);
            response->set_minor(0);
            response->set_patch(0);
            return ::grpc::Status::OK;
        }
    };
    TestService service;
    std::ostringstream server_address;
    server_address << "localhost:" << 12345; // TODO(canepat): grpc_pick_unused_port_or_die
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address.str(), grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    const auto server_ptr = builder.BuildAndStart();
    const auto channel = grpc::CreateChannel(server_address.str(), grpc::InsecureChannelCredentials());
    const auto version_result{wait_for_kv_protocol_check(channel)};
    server_ptr->Shutdown();
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("MINING protocol version error", "[silkrpc][protocol][wait_for_mining_protocol_check]") {
    std::unique_ptr<::txpool::Mining::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockMiningStub>()};

    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockMiningStub*>(stub.get()), Version(_, _, _)).WillOnce(
        Return(grpc::Status::CANCELLED));
    const auto version_result{wait_for_mining_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("MINING protocol version major mismatch", "[silkrpc][protocol][wait_for_mining_protocol_check]") {
    std::unique_ptr<::txpool::Mining::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockMiningStub>()};
    types::VersionReply reply;

    reply.set_major(0);
    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockMiningStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result1{wait_for_mining_protocol_check(stub)};
    CHECK(version_result1.compatible == false);
    CHECK(version_result1.result.find("incompatible") != std::string::npos);

    reply.set_major(2);
    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockMiningStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result2{wait_for_mining_protocol_check(stub)};
    CHECK(version_result2.compatible == false);
    CHECK(version_result2.result.find("incompatible") != std::string::npos);
}

TEST_CASE("MINING protocol version minor mismatch", "[silkrpc][protocol][wait_for_mining_protocol_check]") {
    std::unique_ptr<::txpool::Mining::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockMiningStub>()};
    types::VersionReply reply;
    reply.set_major(1);

    reply.set_minor(1);
    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockMiningStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_mining_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("MINING protocol version match", "[silkrpc][protocol][wait_for_mining_protocol_check]") {
    std::unique_ptr<::txpool::Mining::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockMiningStub>()};
    types::VersionReply reply;
    reply.set_major(1);
    reply.set_minor(0);

    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockMiningStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_mining_protocol_check(stub)};
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("MINING protocol version with server stub", "[silkrpc][protocol][wait_for_mining_protocol_check]") {
    class TestService : public ::txpool::Mining::Service {
    public:
        ::grpc::Status Version(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response) override {
            response->set_major(1);
            response->set_minor(0);
            response->set_patch(0);
            return ::grpc::Status::OK;
        }
    };
    TestService service;
    std::ostringstream server_address;
    server_address << "localhost:" << 12345; // TODO(canepat): grpc_pick_unused_port_or_die
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address.str(), grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    const auto server_ptr = builder.BuildAndStart();
    const auto channel = grpc::CreateChannel(server_address.str(), grpc::InsecureChannelCredentials());
    const auto version_result{wait_for_mining_protocol_check(channel)};
    server_ptr->Shutdown();
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("TXPOOL protocol version error", "[silkrpc][protocol][wait_for_txpool_protocol_check]") {
    std::unique_ptr<::txpool::Txpool::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockTxpoolStub>()};

    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockTxpoolStub*>(stub.get()), Version(_, _, _)).WillOnce(
        Return(grpc::Status::CANCELLED));
    const auto version_result{wait_for_txpool_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("TXPOOL protocol version major mismatch", "[silkrpc][protocol][wait_for_txpool_protocol_check]") {
    std::unique_ptr<::txpool::Txpool::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockTxpoolStub>()};
    types::VersionReply reply;

    reply.set_major(0);
    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockTxpoolStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result1{wait_for_txpool_protocol_check(stub)};
    CHECK(version_result1.compatible == false);
    CHECK(version_result1.result.find("incompatible") != std::string::npos);

    reply.set_major(2);
    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockTxpoolStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result2{wait_for_txpool_protocol_check(stub)};
    CHECK(version_result2.compatible == false);
    CHECK(version_result2.result.find("incompatible") != std::string::npos);
}

TEST_CASE("TXPOOL protocol version minor mismatch", "[silkrpc][protocol][wait_for_txpool_protocol_check]") {
    std::unique_ptr<::txpool::Txpool::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockTxpoolStub>()};
    types::VersionReply reply;
    reply.set_major(1);

    reply.set_minor(1);
    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockTxpoolStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_txpool_protocol_check(stub)};
    CHECK(version_result.compatible == false);
    CHECK(version_result.result.find("incompatible") != std::string::npos);
}

TEST_CASE("TXPOOL protocol version match", "[silkrpc][protocol][wait_for_txpool_protocol_check]") {
    std::unique_ptr<::txpool::Txpool::StubInterface> stub{std::make_unique<::txpool::FixIssue24351_MockTxpoolStub>()};
    types::VersionReply reply;
    reply.set_major(1);
    reply.set_minor(0);

    EXPECT_CALL(*dynamic_cast<::txpool::FixIssue24351_MockTxpoolStub*>(stub.get()), Version(_, _, _)).WillOnce(
        DoAll(SetArgPointee<2>(reply), Return(grpc::Status::OK)));
    const auto version_result{wait_for_txpool_protocol_check(stub)};
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

TEST_CASE("TXPOOL protocol version with server stub", "[silkrpc][protocol][wait_for_txpool_protocol_check]") {
    class TestService : public ::txpool::Txpool::Service {
    public:
        ::grpc::Status Version(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response) override {
            response->set_major(1);
            response->set_minor(0);
            response->set_patch(0);
            return ::grpc::Status::OK;
        }
    };
    TestService service;
    std::ostringstream server_address;
    server_address << "localhost:" << 12345; // TODO(canepat): grpc_pick_unused_port_or_die
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address.str(), grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    const auto server_ptr = builder.BuildAndStart();
    const auto channel = grpc::CreateChannel(server_address.str(), grpc::InsecureChannelCredentials());
    const auto version_result{wait_for_txpool_protocol_check(channel)};
    server_ptr->Shutdown();
    CHECK(version_result.compatible == true);
    CHECK(version_result.result.find("incompatible") == std::string::npos);
    CHECK(version_result.result.find("compatible") != std::string::npos);
}

} // namespace silkrpc

