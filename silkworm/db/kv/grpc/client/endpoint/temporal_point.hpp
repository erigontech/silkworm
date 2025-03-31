// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/remote/kv.pb.h>

#include "../../../api/endpoint/temporal_point.hpp"

namespace silkworm::db::kv::grpc::client {

::remote::HistorySeekReq make_history_seek_req(const api::HistoryPointRequest&);
api::HistoryPointResult history_seek_result_from_response(const ::remote::HistorySeekReply&);

::remote::GetLatestReq make_get_latest_req(const api::GetLatestRequest&);
api::GetLatestResult get_latest_result_from_response(const ::remote::GetLatestReply&);

::remote::GetLatestReq make_get_as_of_req(const api::GetAsOfRequest&);
api::GetAsOfResult get_as_of_result_from_response(const ::remote::GetLatestReply&);

}  // namespace silkworm::db::kv::grpc::client
