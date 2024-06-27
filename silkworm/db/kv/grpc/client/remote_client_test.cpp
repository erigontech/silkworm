/*
   Copyright 2024 The Silkworm Authors

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

#include "remote_client.hpp"

#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/infra/grpc/test_util/interfaces/kv_mock_fix24351.grpc.pb.h>
#include <silkworm/infra/grpc/test_util/test_runner.hpp>

#include "../test_util/sample_protos.hpp"

namespace silkworm::db::kv::grpc::client {

using namespace silkworm::grpc::test_util;
using namespace silkworm::db::kv::test_util;
namespace proto = ::remote;

using StrictMockKVStub = testing::StrictMock<proto::FixIssue24351_MockKVStub>;
using RemoteClientTestRunner = TestRunner<RemoteClient, StrictMockKVStub>;

TEST_CASE_METHOD(RemoteClientTestRunner, "KV::HistoryGet", "[node][remote][kv][grpc]") {
    const api::HistoryPointQuery query{};  // input query doesn't matter here, we tweak the reply

    rpc::test::StrictMockAsyncResponseReader<proto::HistoryGetReply> reader;
    EXPECT_CALL(*stub_, AsyncHistoryGetRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_history and get result") {
        proto::HistoryGetReply reply{sample_proto_history_get_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        const api::HistoryPointResult result = run_service_method<&api::Service::get_history>(query);
        CHECK(result.success);
        CHECK(result.value == from_hex("ff00ff00"));
    }
    SECTION("call get_history and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        const api::HistoryPointResult result = run_service_method<&api::Service::get_history>(query);
        CHECK_FALSE(result.success);
        CHECK(result.value.empty());
    }
    SECTION("call get_history and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS((run_service_method<&api::Service::get_history>(query)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(RemoteClientTestRunner, "KV::DomainGet", "[node][remote][kv][grpc]") {
    const api::DomainPointQuery query{};  // input query doesn't matter here, we tweak the reply

    rpc::test::StrictMockAsyncResponseReader<proto::DomainGetReply> reader;
    EXPECT_CALL(*stub_, AsyncDomainGetRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_domain and get result") {
        proto::DomainGetReply reply{sample_proto_domain_get_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        const api::DomainPointResult result = run_service_method<&api::Service::get_domain>(query);
        CHECK(result.success);
        CHECK(result.value == from_hex("ff00ff00"));
    }
    SECTION("call get_domain and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        const api::DomainPointResult result = run_service_method<&api::Service::get_domain>(query);
        CHECK_FALSE(result.success);
        CHECK(result.value.empty());
    }
    SECTION("call get_domain and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS((run_service_method<&api::Service::get_domain>(query)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(RemoteClientTestRunner, "KV::IndexRange", "[node][remote][kv][grpc]") {
    const api::IndexRangeQuery query{};  // input query doesn't matter here, we tweak the reply

    rpc::test::StrictMockAsyncResponseReader<proto::IndexRangeReply> reader;
    EXPECT_CALL(*stub_, AsyncIndexRangeRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_index_range and get result") {
        proto::IndexRangeReply reply{sample_proto_index_range_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        const api::IndexRangeResult result = run_service_method<&api::Service::get_index_range>(query);
        CHECK(result.timestamps == std::vector<api::Timestamp>{1234567, 1234568});
        CHECK(result.next_page_token == "token2");
    }
    SECTION("call get_index_range and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        const api::IndexRangeResult result = run_service_method<&api::Service::get_index_range>(query);
        CHECK(result.timestamps.empty());
        CHECK(result.next_page_token.empty());
    }
    SECTION("call get_index_range and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS((run_service_method<&api::Service::get_index_range>(query)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(RemoteClientTestRunner, "KV::HistoryRange", "[node][remote][kv][grpc]") {
    const api::HistoryRangeQuery query{};  // input query doesn't matter here, we tweak the reply

    rpc::test::StrictMockAsyncResponseReader<proto::Pairs> reader;
    EXPECT_CALL(*stub_, AsyncHistoryRangeRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_history_range and get result") {
        proto::Pairs reply{sample_proto_history_range_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        const api::HistoryRangeResult result = run_service_method<&api::Service::get_history_range>(query);
        CHECK(result.keys == std::vector<Bytes>{*from_hex("00110011AA"), *from_hex("00110011BB")});
        CHECK(result.values == std::vector<Bytes>{*from_hex("00110011EE"), *from_hex("00110011FF")});
        CHECK(result.next_page_token == "token2");
    }
    SECTION("call get_history_range and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        const api::HistoryRangeResult result = run_service_method<&api::Service::get_history_range>(query);
        CHECK(result.keys.empty());
        CHECK(result.values.empty());
        CHECK(result.next_page_token.empty());
    }
    SECTION("call get_history_range and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS((run_service_method<&api::Service::get_history_range>(query)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(RemoteClientTestRunner, "KV::DomainRange", "[node][remote][kv][grpc]") {
    const api::DomainRangeQuery query{};  // input query doesn't matter here, we tweak the reply

    rpc::test::StrictMockAsyncResponseReader<proto::Pairs> reader;
    EXPECT_CALL(*stub_, AsyncDomainRangeRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_domain_range and get result") {
        proto::Pairs reply{sample_proto_domain_range_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        const api::DomainRangeResult result = run_service_method<&api::Service::get_domain_range>(query);
        CHECK(result.keys == std::vector<Bytes>{*from_hex("00110011AA"), *from_hex("00110011BB")});
        CHECK(result.values == std::vector<Bytes>{*from_hex("00110011EE"), *from_hex("00110011FF")});
        CHECK(result.next_page_token == "token2");
    }
    SECTION("call get_domain_range and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        const api::DomainRangeResult result = run_service_method<&api::Service::get_domain_range>(query);
        CHECK(result.keys.empty());
        CHECK(result.values.empty());
        CHECK(result.next_page_token.empty());
    }
    SECTION("call get_domain_range and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS((run_service_method<&api::Service::get_domain_range>(query)), rpc::GrpcStatusError);
    }
}

}  // namespace silkworm::db::kv::grpc::client
