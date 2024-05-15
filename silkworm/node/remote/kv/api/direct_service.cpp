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

#include "direct_service.hpp"

namespace silkworm::remote::kv::api {

DirectService::DirectService() = default;

/** Temporal Point Queries **/
    
// rpc HistoryGet(HistoryGetReq) returns (HistoryGetReply);
Task<HistoryPointResult> DirectService::get_history(const HistoryPointQuery&) {
    // TODO(canepat) implement
    co_return HistoryPointResult{};
}

// rpc DomainGet(DomainGetReq) returns (DomainGetReply);
Task<DomainPointResult> DirectService::get_domain(const DomainPointQuery&) {
    // TODO(canepat) implement
    co_return DomainPointResult{};
}

/** Temporal Range Queries **/

// rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
Task<IndexRangeResult> DirectService::get_index_range(const IndexRangeQuery&) {
    // TODO(canepat) implement
    co_return IndexRangeResult{};
}

// rpc HistoryRange(HistoryRangeReq) returns (Pairs);
Task<HistoryRangeResult> DirectService::get_history_range(const HistoryRangeQuery&) {
    // TODO(canepat) implement
    co_return HistoryRangeResult{};
}

// rpc DomainRange(DomainRangeReq) returns (Pairs);
Task<DomainRangeResult> DirectService::get_domain_range(const DomainRangeQuery&) {
    // TODO(canepat) implement
    co_return DomainRangeResult{};
}

}  // namespace silkworm::remote::kv::api
