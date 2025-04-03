// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "temporal_point.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm::db::kv::grpc::client {

namespace proto = ::remote;

proto::HistorySeekReq make_history_seek_req(const api::HistoryPointRequest& request) {
    proto::HistorySeekReq req;
    req.set_tx_id(request.tx_id);
    req.set_table(request.table);
    req.set_k(request.key.data(), request.key.size());
    req.set_ts(static_cast<uint64_t>(request.timestamp));
    return req;
}

api::HistoryPointResult history_seek_result_from_response(const proto::HistorySeekReply& response) {
    api::HistoryPointResult result;
    result.success = response.ok();
    result.value = string_to_bytes(response.v());
    return result;
}

proto::GetLatestReq make_get_latest_req(const api::GetLatestRequest& request) {
    proto::GetLatestReq req;
    req.set_tx_id(request.tx_id);
    req.set_table(request.table);
    req.set_k(request.key.data(), request.key.size());
    req.set_latest(true);
    req.set_k2(request.sub_key.data(), request.sub_key.size());
    return req;
}

api::GetLatestResult get_latest_result_from_response(const proto::GetLatestReply& response) {
    api::GetLatestResult result;
    result.success = !response.v().empty();
    result.value = string_to_bytes(response.v());
    return result;
}

::remote::GetLatestReq make_get_as_of_req(const api::GetAsOfRequest& request) {
    proto::GetLatestReq req;
    req.set_tx_id(request.tx_id);
    req.set_table(request.table);
    req.set_k(request.key.data(), request.key.size());
    req.set_ts(static_cast<uint64_t>(request.timestamp));
    req.set_k2(request.sub_key.data(), request.sub_key.size());
    return req;
}

api::GetAsOfResult get_as_of_result_from_response(const ::remote::GetLatestReply& response) {
    api::GetAsOfResult result;
    result.success = response.ok();
    result.value = string_to_bytes(response.v());
    return result;
}

}  // namespace silkworm::db::kv::grpc::client
