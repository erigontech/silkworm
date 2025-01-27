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

#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;

proto::HistorySeekReq history_seek_request_from_query(const api::HistoryPointQuery& query) {
    proto::HistorySeekReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_k(query.key.data(), query.key.size());
    request.set_ts(static_cast<uint64_t>(query.timestamp));
    return request;
}

api::HistoryPointResult history_seek_result_from_response(const proto::HistorySeekReply& response) {
    api::HistoryPointResult result;
    result.success = response.ok();
    result.value = string_to_bytes(response.v());
    return result;
}

proto::GetLatestReq get_latest_request_from_query(const api::GetLatestQuery& query) {
    proto::GetLatestReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_k(query.key.data(), query.key.size());
    request.set_latest(true);
    request.set_k2(query.sub_key.data(), query.sub_key.size());
    return request;
}

api::GetLatestResult get_latest_result_from_response(const proto::GetLatestReply& response) {
    api::GetLatestResult result;
    result.success = true;
    result.value = string_to_bytes(response.v());
    return result;
}

::remote::GetLatestReq get_as_of_request_from_query(const api::GetAsOfQuery& query) {
    proto::GetLatestReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_k(query.key.data(), query.key.size());
    request.set_ts(static_cast<uint64_t>(query.timestamp));
    request.set_k2(query.sub_key.data(), query.sub_key.size());
    return request;
}

api::GetAsOfResult get_as_of_result_from_response(const ::remote::GetLatestReply& response) {
    api::GetAsOfResult result;
    result.success = response.ok();
    result.value = string_to_bytes(response.v());
    return result;
}

}  // namespace silkworm::db::kv::grpc::client
