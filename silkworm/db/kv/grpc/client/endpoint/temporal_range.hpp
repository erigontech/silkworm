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
