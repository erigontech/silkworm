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

#include "../../../api/endpoint/temporal_point.hpp"

namespace silkworm::db::kv::grpc::client {

::remote::HistorySeekReq make_history_seek_req(const api::HistoryPointRequest&);
api::HistoryPointResult history_seek_result_from_response(const ::remote::HistorySeekReply&);

::remote::GetLatestReq make_get_latest_req(const api::GetLatestRequest&);
api::GetLatestResult get_latest_result_from_response(const ::remote::GetLatestReply&);

::remote::GetLatestReq make_get_as_of_req(const api::GetAsOfRequest&);
api::GetAsOfResult get_as_of_result_from_response(const ::remote::GetLatestReply&);

}  // namespace silkworm::db::kv::grpc::client
