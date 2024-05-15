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

#include <silkworm/core/common/util.hpp>

namespace silkworm::remote::kv::grpc::client {

namespace proto = ::remote;

proto::HistoryGetReq history_get_request_from_query(const api::HistoryPointQuery& query) {
    proto::HistoryGetReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_k(to_hex(query.key));
    request.set_ts(static_cast<uint64_t>(query.timestamp));
    return request;
}

api::HistoryPointResult history_get_result_from_response(const proto::HistoryGetReply& response) {
    api::HistoryPointResult result;
    result.success = response.ok();
    auto hex{from_hex(response.v())};
    if (hex) {
        result.value = std::move(*hex);
    }
    return result;
}

proto::DomainGetReq domain_get_request_from_query(const api::DomainPointQuery& query) {
    proto::DomainGetReq request;
    request.set_tx_id(query.tx_id);
    request.set_table(query.table);
    request.set_k(to_hex(query.key));
    if (query.timestamp) {
        request.set_ts(static_cast<uint64_t>(*query.timestamp));
    } else {
        request.set_latest(true);
    }
    request.set_k2(to_hex(query.sub_key));
    return request;
}

api::DomainPointResult domain_get_result_from_response(const proto::DomainGetReply& response) {
    api::DomainPointResult result;
    result.success = response.ok();
    auto hex{from_hex(response.v())};
    if (hex) {
        result.value = std::move(*hex);
    }
    return result;
}

}  // namespace silkworm::remote::kv::grpc::client
