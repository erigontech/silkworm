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

#include "temporal_point.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/fixture.hpp>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::db::kv::grpc::client {

using namespace evmc::literals;
using namespace silkworm::db::kv::test_util;
using namespace silkworm::test_util;
namespace proto = ::remote;

TEST_CASE("make_history_seek_req", "[node][remote][kv][grpc]") {
    const Fixtures<api::HistoryPointRequest, proto::HistorySeekReq> fixtures{
        {{}, {}},
        {sample_history_point_request(), sample_proto_history_seek_request()},
    };
    for (const auto& [request, expected_req] : fixtures) {
        SECTION("request: " + std::to_string(request.tx_id)) {
            const auto& point_request{make_history_seek_req(request)};
            // CHECK(point_request == expected_point_request);  // requires operator== in gRPC
            CHECK(point_request.tx_id() == expected_req.tx_id());
            CHECK(point_request.table() == expected_req.table());
            CHECK(point_request.k() == expected_req.k());
            CHECK(point_request.ts() == expected_req.ts());
        }
    }
}

TEST_CASE("history_get_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::HistorySeekReply, api::HistoryPointResult> fixtures{
        {{}, {}},
        {sample_proto_history_seek_response(), sample_history_point_result()},
    };
    for (const auto& [response, expected_point_result] : fixtures) {
        SECTION("ok: " + std::to_string(response.ok())) {
            const auto& point_result{history_seek_result_from_response(response)};
            // CHECK(point_result == expected_point_result);  // requires operator== in gRPC
            CHECK(point_result.success == expected_point_result.success);
            CHECK(point_result.value == expected_point_result.value);
        }
    }
}

TEST_CASE("make_get_as_of_req", "[node][remote][kv][grpc]") {
    const Fixtures<api::GetAsOfRequest, proto::GetLatestReq> fixtures{
        {sample_get_as_of_request(), sample_proto_get_as_of_request()},
    };
    for (const auto& [request, expected_req] : fixtures) {
        SECTION("request: " + std::to_string(request.tx_id)) {
            const auto& point_request{make_get_as_of_req(request)};
            // CHECK(point_request == expected_point_request);  // requires operator== in gRPC
            CHECK(point_request.tx_id() == expected_req.tx_id());
            CHECK(point_request.table() == expected_req.table());
            CHECK(point_request.k() == expected_req.k());
            CHECK(point_request.ts() == expected_req.ts());
            CHECK(point_request.latest() == expected_req.latest());
            CHECK(point_request.k2() == expected_req.k2());
        }
    }
}

TEST_CASE("get_as_of_result_from_response", "[node][remote][kv][grpc]") {
    const Fixtures<proto::GetLatestReply, api::GetAsOfResult> fixtures{
        {{}, {}},
        {sample_proto_get_as_of_response(), sample_get_as_of_result()},
    };
    for (const auto& [response, expected_point_result] : fixtures) {
        SECTION("ok: " + std::to_string(response.ok())) {
            const auto& point_result{get_as_of_result_from_response(response)};
            // CHECK(point_result == expected_point_result);  // requires operator== in gRPC
            CHECK(point_result.success == expected_point_result.success);
            CHECK(point_result.value == expected_point_result.value);
        }
    }
}

}  // namespace silkworm::db::kv::grpc::client
