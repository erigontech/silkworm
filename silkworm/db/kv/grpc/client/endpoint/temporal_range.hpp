// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/remote/kv.pb.h>

#include "../../../api/endpoint/temporal_range.hpp"

namespace silkworm::db::kv::grpc::client {

::remote::IndexRangeReq make_index_range_req(const api::IndexRangeRequest&);
api::IndexRangeResult index_range_result_from_response(const ::remote::IndexRangeReply&);

::remote::HistoryRangeReq make_history_range_req(const api::HistoryRangeRequest&);
api::HistoryRangeResult history_range_result_from_response(const ::remote::Pairs&);

::remote::RangeAsOfReq make_domain_range_req(const api::DomainRangeRequest&);
api::DomainRangeResult domain_range_result_from_response(const ::remote::Pairs&);

}  // namespace silkworm::db::kv::grpc::client
