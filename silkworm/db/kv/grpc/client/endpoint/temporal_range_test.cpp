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

#include "temporal_range.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/fixture.hpp>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::db::kv::grpc::client {

using namespace evmc::literals;
using namespace silkworm::db::kv::test_util;
using namespace silkworm::test_util;
namespace proto = ::remote;

TEST_CASE("index_range_request_from_query", "[node][remote][kv][grpc]") {
    const Fixtures<api::IndexRangeQuery, proto::IndexRangeReq> fixtures{
        {{}, default_proto_index_range_request()},
        {sample_index_range_query(), sample_proto_index_range_request()},
    };
    for (const auto& [query, expected_range_request] : fixtures) {
        SECTION("query: " + std::to_string(query.tx_id)) {
            const auto& range_request{index_range_request_from_query(query)};
            // CHECK(range_request == expected_range_request);  // requires operator== in gRPC
            CHECK(range_request.tx_id() == expected_range_request.tx_id());
            CHECK(range_request.table() == expected_range_request.table());
            CHECK(range_request.k() == expected_range_request.k());
            CHECK(range_request.from_ts() == expected_range_request.from_ts());
            CHECK(range_request.to_ts() == expected_range_request.to_ts());
            CHECK(range_request.order_ascend() == expected_range_request.order_ascend());
            CHECK(range_request.limit() == expected_range_request.limit());
            CHECK(range_request.page_size() == expected_range_request.page_size());
            CHECK(range_request.page_token() == expected_range_request.page_token());
        }
    }
}

TEST_CASE("index_range_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::IndexRangeReply, api::IndexRangeResult> fixtures{
        {{}, {}},
        {sample_proto_index_range_response(), sample_index_range_result()},
    };
    for (const auto& [response, expected_range_result] : fixtures) {
        SECTION("query: " + response.next_page_token()) {
            const auto& range_result{index_range_result_from_response(response)};
            // CHECK(range_result == expected_range_result);  // requires operator== in gRPC
            CHECK(range_result.timestamps == expected_range_result.timestamps);
            CHECK(range_result.next_page_token == expected_range_result.next_page_token);
        }
    }
}

TEST_CASE("history_range_request_from_query", "[node][remote][kv][grpc]") {
    const Fixtures<api::HistoryRangeQuery, proto::HistoryRangeReq> fixtures{
        {{}, default_proto_history_range_request()},
        {sample_history_range_query(), sample_proto_history_range_request()},
    };
    for (const auto& [query, expected_range_request] : fixtures) {
        SECTION("query: " + std::to_string(query.tx_id)) {
            const auto& range_request{history_range_request_from_query(query)};
            // CHECK(range_request == expected_range_request);  // requires operator== in gRPC
            CHECK(range_request.tx_id() == expected_range_request.tx_id());
            CHECK(range_request.table() == expected_range_request.table());
            CHECK(range_request.from_ts() == expected_range_request.from_ts());
            CHECK(range_request.to_ts() == expected_range_request.to_ts());
            CHECK(range_request.order_ascend() == expected_range_request.order_ascend());
            CHECK(range_request.limit() == expected_range_request.limit());
            CHECK(range_request.page_size() == expected_range_request.page_size());
            CHECK(range_request.page_token() == expected_range_request.page_token());
        }
    }
}

TEST_CASE("history_range_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::Pairs, api::HistoryRangeResult> fixtures{
        {{}, {}},
        {sample_proto_history_range_response(), sample_history_range_result()},
    };
    for (const auto& [response, expected_range_result] : fixtures) {
        SECTION("query: " + response.next_page_token()) {
            const auto& range_result{history_range_result_from_response(response)};
            // CHECK(range_result == expected_range_result);  // requires operator== in gRPC
            CHECK(range_result.keys == expected_range_result.keys);
            CHECK(range_result.values == expected_range_result.values);
            CHECK(range_result.next_page_token == expected_range_result.next_page_token);
        }
    }
}

TEST_CASE("domain_range_request_from_query", "[node][remote][kv][grpc]") {
    const Fixtures<api::DomainRangeQuery, proto::DomainRangeReq> fixtures{
        {{}, default_proto_domain_range_request()},
        {sample_domain_range_query(), sample_proto_domain_range_request()},
    };
    for (const auto& [query, expected_range_request] : fixtures) {
        SECTION("query: " + std::to_string(query.tx_id)) {
            const auto& range_request{domain_range_request_from_query(query)};
            // CHECK(range_request == expected_range_request);  // requires operator== in gRPC
            CHECK(range_request.tx_id() == expected_range_request.tx_id());
            CHECK(range_request.table() == expected_range_request.table());
            CHECK(range_request.from_key() == expected_range_request.from_key());
            CHECK(range_request.to_key() == expected_range_request.to_key());
            CHECK(range_request.order_ascend() == expected_range_request.order_ascend());
            CHECK(range_request.limit() == expected_range_request.limit());
            CHECK(range_request.page_size() == expected_range_request.page_size());
            CHECK(range_request.page_token() == expected_range_request.page_token());
        }
    }
}

TEST_CASE("domain_range_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::Pairs, api::DomainRangeResult> fixtures{
        {{}, {}},
        {sample_proto_domain_range_response(), sample_domain_range_result()},
    };
    for (const auto& [response, expected_range_result] : fixtures) {
        SECTION("query: " + response.next_page_token()) {
            const auto& range_result{domain_range_result_from_response(response)};
            // CHECK(range_result == expected_range_result);  // requires operator== in gRPC
            CHECK(range_result.keys == expected_range_result.keys);
            CHECK(range_result.values == expected_range_result.values);
            CHECK(range_result.next_page_token == expected_range_result.next_page_token);
        }
    }
}

}  // namespace silkworm::db::kv::grpc::client
