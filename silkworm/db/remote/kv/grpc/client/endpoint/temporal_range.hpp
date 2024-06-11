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

namespace silkworm::remote::kv::grpc::client {

::remote::IndexRangeReq index_range_request_from_query(const api::IndexRangeQuery&);
api::IndexRangeResult index_range_result_from_response(const ::remote::IndexRangeReply&);

::remote::HistoryRangeReq history_range_request_from_query(const api::HistoryRangeQuery&);
api::HistoryRangeResult history_range_result_from_response(const ::remote::Pairs&);

::remote::DomainRangeReq domain_range_request_from_query(const api::DomainRangeQuery&);
api::DomainRangeResult domain_range_result_from_response(const ::remote::Pairs&);

}  // namespace silkworm::remote::kv::grpc::client
