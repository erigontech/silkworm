// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "temporal_range.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/fixture.hpp>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::db::kv::grpc::client {

using namespace evmc::literals;
using namespace silkworm::db::kv::test_util;
using namespace silkworm::test_util;
namespace proto = ::remote;

TEST_CASE("make_index_range_req", "[node][remote][kv][grpc]") {
    const Fixtures<api::IndexRangeRequest, proto::IndexRangeReq> fixtures{
        {{}, default_proto_index_range_request()},
        {sample_index_range_request(), sample_proto_index_range_request()},
    };
    for (const auto& [request, expected_req] : fixtures) {
        SECTION("request: " + std::to_string(request.tx_id)) {
            const auto& range_request{make_index_range_req(request)};
            // CHECK(range_request == expected_range_request);  // requires operator== in gRPC
            CHECK(range_request.tx_id() == expected_req.tx_id());
            CHECK(range_request.table() == expected_req.table());
            CHECK(range_request.k() == expected_req.k());
            CHECK(range_request.from_ts() == expected_req.from_ts());
            CHECK(range_request.to_ts() == expected_req.to_ts());
            CHECK(range_request.order_ascend() == expected_req.order_ascend());
            CHECK(range_request.limit() == expected_req.limit());
            CHECK(range_request.page_size() == expected_req.page_size());
            CHECK(range_request.page_token() == expected_req.page_token());
        }
    }
}

TEST_CASE("index_range_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::IndexRangeReply, api::IndexRangeResult> fixtures{
        {{}, {}},
        {sample_proto_index_range_response(), sample_index_range_result()},
    };
    for (const auto& [response, expected_range_result] : fixtures) {
        SECTION("response: " + response.next_page_token()) {
            const auto& range_result{index_range_result_from_response(response)};
            // CHECK(range_result == expected_range_result);  // requires operator== in gRPC
            CHECK(range_result.timestamps == expected_range_result.timestamps);
            CHECK(range_result.next_page_token == expected_range_result.next_page_token);
        }
    }
}

TEST_CASE("make_history_range_req", "[node][remote][kv][grpc]") {
    const Fixtures<api::HistoryRangeRequest, proto::HistoryRangeReq> fixtures{
        {{}, default_proto_history_range_request()},
        {sample_history_range_request(), sample_proto_history_range_request()},
    };
    for (const auto& [request, expected_req] : fixtures) {
        SECTION("request: " + std::to_string(request.tx_id)) {
            const auto& range_request{make_history_range_req(request)};
            // CHECK(range_request == expected_range_request);  // requires operator== in gRPC
            CHECK(range_request.tx_id() == expected_req.tx_id());
            CHECK(range_request.table() == expected_req.table());
            CHECK(range_request.from_ts() == expected_req.from_ts());
            CHECK(range_request.to_ts() == expected_req.to_ts());
            CHECK(range_request.order_ascend() == expected_req.order_ascend());
            CHECK(range_request.limit() == expected_req.limit());
            CHECK(range_request.page_size() == expected_req.page_size());
            CHECK(range_request.page_token() == expected_req.page_token());
        }
    }
}

TEST_CASE("history_range_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::Pairs, api::HistoryRangeResult> fixtures{
        {{}, {}},
        {sample_proto_history_range_response(), sample_history_range_result()},
    };
    for (const auto& [response, expected_range_result] : fixtures) {
        SECTION("response: " + response.next_page_token()) {
            const auto& range_result{history_range_result_from_response(response)};
            // CHECK(range_result == expected_range_result);  // requires operator== in gRPC
            CHECK(range_result.keys == expected_range_result.keys);
            CHECK(range_result.values == expected_range_result.values);
            CHECK(range_result.next_page_token == expected_range_result.next_page_token);
        }
    }
}

TEST_CASE("make_domain_range_req", "[node][remote][kv][grpc]") {
    const Fixtures<api::DomainRangeRequest, proto::RangeAsOfReq> fixtures{
        {{}, default_proto_domain_range_request()},
        {sample_domain_range_request(), sample_proto_domain_range_request()},
    };
    for (const auto& [request, expected_req] : fixtures) {
        SECTION("request: " + std::to_string(request.tx_id)) {
            const auto& range_request{make_domain_range_req(request)};
            // CHECK(range_request == expected_range_request);  // requires operator== in gRPC
            CHECK(range_request.tx_id() == expected_req.tx_id());
            CHECK(range_request.table() == expected_req.table());
            CHECK(range_request.from_key() == expected_req.from_key());
            CHECK(range_request.to_key() == expected_req.to_key());
            CHECK(range_request.ts() == expected_req.ts());
            CHECK(range_request.order_ascend() == expected_req.order_ascend());
            CHECK(range_request.limit() == expected_req.limit());
            CHECK(range_request.page_size() == expected_req.page_size());
            CHECK(range_request.page_token() == expected_req.page_token());
        }
    }
}

TEST_CASE("domain_range_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::Pairs, api::DomainRangeResult> fixtures{
        {{}, {}},
        {sample_proto_domain_range_response(), sample_domain_range_result()},
    };
    for (const auto& [response, expected_range_result] : fixtures) {
        SECTION("response: " + response.next_page_token()) {
            const auto& range_result{domain_range_result_from_response(response)};
            // CHECK(range_result == expected_range_result);  // requires operator== in gRPC
            CHECK(range_result.keys == expected_range_result.keys);
            CHECK(range_result.values == expected_range_result.values);
            CHECK(range_result.next_page_token == expected_range_result.next_page_token);
        }
    }
}

}  // namespace silkworm::db::kv::grpc::client
