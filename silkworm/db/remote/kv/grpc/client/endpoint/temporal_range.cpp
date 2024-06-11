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

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/grpc/common/bytes.hpp>

namespace silkworm::remote::kv::grpc::client {

namespace proto = ::remote;

proto::IndexRangeReq index_range_request_from_query(const api::IndexRangeQuery& query) {
    proto::IndexRangeReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_k(to_hex(query.key));
    request.set_from_ts(query.from_timestamp);
    request.set_to_ts(query.to_timestamp);
    request.set_order_ascend(query.ascending_order);
    request.set_limit(static_cast<int64_t>(query.limit));
    request.set_page_size(static_cast<int32_t>(query.page_size));
    request.set_page_token(query.page_token);
    return request;
}

api::IndexRangeResult index_range_result_from_response(const proto::IndexRangeReply& response) {
    api::IndexRangeResult result;
    for (const auto ts : response.timestamps()) {
        result.timestamps.push_back(static_cast<int64_t>(ts));
    }
    result.next_page_token = response.next_page_token();
    return result;
}

proto::HistoryRangeReq history_range_request_from_query(const api::HistoryRangeQuery& query) {
    proto::HistoryRangeReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_from_ts(query.from_timestamp);
    request.set_to_ts(query.to_timestamp);
    request.set_order_ascend(query.ascending_order);
    request.set_limit(static_cast<int64_t>(query.limit));
    request.set_page_size(static_cast<int32_t>(query.page_size));
    request.set_page_token(query.page_token);
    return request;
}

api::HistoryRangeResult history_range_result_from_response(const proto::Pairs& response) {
    api::HistoryRangeResult result;
    for (const auto& hex_key : response.keys()) {
        rpc::deserialize_hex_as_bytes(hex_key, result.keys);
    }
    for (const auto& hex_value : response.values()) {
        rpc::deserialize_hex_as_bytes(hex_value, result.values);
    }
    result.next_page_token = response.next_page_token();
    return result;
}

::remote::DomainRangeReq domain_range_request_from_query(const api::DomainRangeQuery& query) {
    ::remote::DomainRangeReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_from_key(to_hex(query.from_key));
    request.set_to_key(to_hex(query.to_key));
    request.set_order_ascend(query.ascending_order);
    request.set_limit(static_cast<int64_t>(query.limit));
    request.set_page_size(static_cast<int32_t>(query.page_size));
    request.set_page_token(query.page_token);
    return request;
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

}  // namespace silkworm::remote::kv::grpc::client
