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

#pragma once

#include <string>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/test_util/hex.hpp>
#include <silkworm/interfaces/remote/kv.pb.h>

#include "../../api/endpoint/temporal_point.hpp"
#include "../../api/endpoint/temporal_range.hpp"

namespace silkworm::db::kv::test_util {

namespace proto = ::remote;
using silkworm::test_util::ascii_from_hex;

inline api::HistoryPointRequest sample_history_point_request() {
    return {
        .tx_id = 1,
        .table = "AAA",
        .key = {0x00, 0x11, 0xff},
        .timestamp = 1234567,
    };
}

inline proto::HistorySeekReq sample_proto_history_seek_request() {
    proto::HistorySeekReq request;
    request.set_tx_id(1);
    request.set_table("AAA");
    request.set_k(ascii_from_hex("0011ff"));
    request.set_ts(1234567);
    return request;
}

inline proto::HistorySeekReply sample_proto_history_seek_response() {
    proto::HistorySeekReply response;
    response.set_ok(true);
    response.set_v(ascii_from_hex("ff00ff00"));
    return response;
}

inline api::HistoryPointResult sample_history_point_result() {
    return {
        .success = true,
        .value = {0xff, 0x00, 0xff, 0x00},
    };
}

inline api::GetAsOfRequest sample_get_latest_request() {
    return {
        .tx_id = 1,
        .table = "AAA",
        .key = {0x00, 0x11, 0xff},
        .sub_key = {0x00, 0x11, 0x22},
    };
}

inline api::GetAsOfRequest sample_get_as_of_request() {
    return {
        .tx_id = 1,
        .table = "AAA",
        .key = {0x00, 0x11, 0xff},
        .sub_key = {0x00, 0x11, 0x22},
        .timestamp = 1234567,
    };
}

inline proto::GetLatestReq sample_proto_get_latest_request() {
    proto::GetLatestReq request;
    request.set_tx_id(1);
    request.set_table("AAA");
    request.set_k(ascii_from_hex("0011ff"));
    request.set_latest(true);
    request.set_k2(ascii_from_hex("001122"));
    return request;
}

inline proto::GetLatestReq sample_proto_get_as_of_request() {
    proto::GetLatestReq request;
    request.set_tx_id(1);
    request.set_table("AAA");
    request.set_k(ascii_from_hex("0011ff"));
    request.set_ts(1234567);
    request.set_k2(ascii_from_hex("001122"));
    return request;
}

inline proto::GetLatestReply sample_proto_get_latest_response() {
    proto::GetLatestReply response;
    response.set_ok(true);
    response.set_v(ascii_from_hex("ff00ff00"));
    return response;
}

inline proto::GetLatestReply sample_proto_get_as_of_response() {
    proto::GetLatestReply response;
    response.set_ok(true);
    response.set_v(ascii_from_hex("ff00ff00"));
    return response;
}

inline api::GetLatestResult sample_get_latest_result() {
    return {
        .success = true,
        .value = {0xff, 0x00, 0xff, 0x00},
    };
}

inline api::GetAsOfResult sample_get_as_of_result() {
    return {
        .success = true,
        .value = {0xff, 0x00, 0xff, 0x00},
    };
}

inline api::IndexRangeRequest sample_index_range_request() {
    return {
        .tx_id = 1,
        .table = "AAA",
        .key = {0x00, 0x11, 0xff},
        .from_timestamp = 1234567,
        .to_timestamp = 1234967,
        .ascending_order = true,
        .limit = 1'000,
        .page_size = 100,
        .page_token = "token1",
    };
}

inline proto::IndexRangeReq default_proto_index_range_request() {
    proto::IndexRangeReq request;
    request.set_limit(api::kUnlimited);  // default value for type is 0 whilst we're choosing unlimited (-1) in API
    return request;
}

inline proto::IndexRangeReq sample_proto_index_range_request() {
    proto::IndexRangeReq request;
    request.set_tx_id(1);
    request.set_table("AAA");
    request.set_k(ascii_from_hex("0011ff"));
    request.set_from_ts(1234567);
    request.set_to_ts(1234967);
    request.set_order_ascend(true);
    request.set_limit(1'000);
    request.set_page_size(100);
    request.set_page_token("token1");
    return request;
}

inline proto::IndexRangeReply sample_proto_index_range_response() {
    proto::IndexRangeReply response;
    response.set_next_page_token("token2");
    response.add_timestamps(1234567);
    response.add_timestamps(1234568);
    return response;
}

inline api::IndexRangeResult sample_index_range_result() {
    return {
        .timestamps = {1234567, 1234568},
        .next_page_token = "token2",
    };
}

inline api::HistoryRangeRequest sample_history_range_request() {
    return {
        .tx_id = 1,
        .table = "AAA",
        .from_timestamp = 1234567,
        .to_timestamp = 1234967,
        .ascending_order = true,
        .limit = 1'000,
        .page_size = 100,
        .page_token = "token1",
    };
}

inline proto::HistoryRangeReq default_proto_history_range_request() {
    proto::HistoryRangeReq request;
    request.set_limit(api::kUnlimited);  // default value for type is 0 whilst we're choosing unlimited (-1) in API
    return request;
}

inline proto::HistoryRangeReq sample_proto_history_range_request() {
    proto::HistoryRangeReq request;
    request.set_tx_id(1);
    request.set_table("AAA");
    request.set_from_ts(1234567);
    request.set_to_ts(1234967);
    request.set_order_ascend(true);
    request.set_limit(1'000);
    request.set_page_size(100);
    request.set_page_token("token1");
    return request;
}

inline proto::Pairs sample_proto_history_range_response() {
    proto::Pairs response;
    response.add_keys(bytes_to_string(*from_hex("00110011AA")));
    response.add_keys(bytes_to_string(*from_hex("00110011BB")));
    response.add_values(bytes_to_string(*from_hex("00110011EE")));
    response.add_values(bytes_to_string(*from_hex("00110011FF")));
    response.set_next_page_token("token2");
    return response;
}

inline api::HistoryRangeResult sample_history_range_result() {
    return {
        .keys = {{0x00, 0x11, 0x00, 0x11, 0xAA}, {0x00, 0x11, 0x00, 0x11, 0xBB}},
        .values = {{0x00, 0x11, 0x00, 0x11, 0xEE}, {0x00, 0x11, 0x00, 0x11, 0xFF}},
        .next_page_token = "token2",
    };
}

inline api::DomainRangeRequest sample_domain_range_request() {
    return {
        .tx_id = 1,
        .table = "AAA",
        .from_key = {0x00, 0x11, 0xaa},
        .to_key = {0x00, 0x11, 0xff},
        .timestamp = 180'000'000,
        .ascending_order = true,
        .limit = 1'000,
        .page_size = 100,
        .page_token = "token7",
    };
}

inline proto::RangeAsOfReq default_proto_domain_range_request() {
    proto::RangeAsOfReq request;
    request.set_limit(api::kUnlimited);  // default value for type is 0 whilst we're choosing unlimited (-1) in API
    return request;
}

inline proto::RangeAsOfReq sample_proto_domain_range_request() {
    proto::RangeAsOfReq request;
    request.set_tx_id(1);
    request.set_table("AAA");
    request.set_from_key(ascii_from_hex("0011aa"));
    request.set_to_key(ascii_from_hex("0011ff"));
    request.set_ts(180'000'000);
    request.set_order_ascend(true);
    request.set_limit(1'000);
    request.set_page_size(100);
    request.set_page_token("token7");
    return request;
}

inline proto::Pairs sample_proto_domain_range_response() {
    proto::Pairs response;
    response.add_keys("00110011AA");
    response.add_keys("00110011BB");
    response.add_values("00110011EE");
    response.add_values("00110011FF");
    response.set_next_page_token("token2");
    return response;
}

inline api::DomainRangeResult sample_domain_range_result() {
    return {
        .keys = {{0x00, 0x11, 0x00, 0x11, 0xAA}, {0x00, 0x11, 0x00, 0x11, 0xBB}},
        .values = {{0x00, 0x11, 0x00, 0x11, 0xEE}, {0x00, 0x11, 0x00, 0x11, 0xFF}},
        .next_page_token = "token2",
    };
}

}  // namespace silkworm::db::kv::test_util
