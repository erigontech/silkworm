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

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/grpc/common/bytes.hpp>

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;

proto::IndexRangeReq make_index_range_req(const api::IndexRangeRequest& request) {
    proto::IndexRangeReq req;
    req.set_tx_id(request.tx_id);
    req.set_table(request.table);
    req.set_k(request.key.data(), request.key.size());
    req.set_from_ts(request.from_timestamp);
    req.set_to_ts(request.to_timestamp);
    req.set_order_ascend(request.ascending_order);
    req.set_limit(request.limit);
    req.set_page_size(static_cast<int32_t>(request.page_size));
    req.set_page_token(request.page_token);
    return req;
}

api::IndexRangeResult index_range_result_from_response(const proto::IndexRangeReply& response) {
    api::IndexRangeResult result;
    for (const auto ts : response.timestamps()) {
        result.timestamps.push_back(static_cast<int64_t>(ts));
    }
    result.next_page_token = response.next_page_token();
    return result;
}

proto::HistoryRangeReq make_history_range_req(const api::HistoryRangeRequest& request) {
    proto::HistoryRangeReq req;
    req.set_tx_id(request.tx_id);
    req.set_table(request.table);
    req.set_from_ts(request.from_timestamp);
    req.set_to_ts(request.to_timestamp);
    req.set_order_ascend(request.ascending_order);
    req.set_limit(static_cast<int64_t>(request.limit));
    req.set_page_size(static_cast<int32_t>(request.page_size));
    req.set_page_token(request.page_token);
    return req;
}

api::HistoryRangeResult history_range_result_from_response(const proto::Pairs& response) {
    api::HistoryRangeResult result;
    for (const auto& key : response.keys()) {
        result.keys.emplace_back(string_to_bytes(key));
    }
    for (const auto& value : response.values()) {
        result.values.emplace_back(string_to_bytes(value));
    }
    result.next_page_token = response.next_page_token();
    return result;
}

::remote::RangeAsOfReq make_domain_range_req(const api::DomainRangeRequest& request) {
    ::remote::RangeAsOfReq req;
    req.set_tx_id(request.tx_id);
    req.set_table(request.table);
    req.set_from_key(request.from_key.data(), request.from_key.size());
    req.set_to_key(request.to_key.data(), request.to_key.size());
    if (request.timestamp) {
        req.set_ts(static_cast<uint64_t>(*request.timestamp));
    } else {
        req.set_latest(true);
    }
    req.set_order_ascend(request.ascending_order);
    req.set_limit(static_cast<int64_t>(request.limit));
    req.set_page_size(static_cast<int32_t>(request.page_size));
    req.set_page_token(request.page_token);
    return req;
}

api::DomainRangeResult domain_range_result_from_response(const ::remote::Pairs& response) {
    api::DomainRangeResult result;
    for (const auto& hex_key : response.keys()) {
        rpc::deserialize_hex_as_bytes(hex_key, result.keys);
    }
    for (const auto& hex_value : response.values()) {
        rpc::deserialize_hex_as_bytes(hex_value, result.values);
    }
    result.next_page_token = response.next_page_token();
    return result;
}

}  // namespace silkworm::db::kv::grpc::client
