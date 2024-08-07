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

#include <silkworm/infra/concurrency/task.hpp>

#include "endpoint/state_change.hpp"
#include "endpoint/temporal_point.hpp"
#include "endpoint/temporal_range.hpp"
#include "endpoint/version.hpp"
#include "transaction.hpp"

namespace silkworm::db::kv::api {

struct Service {
    virtual ~Service() = default;

    // rpc Version(google.protobuf.Empty) returns (types.VersionReply);
    virtual Task<Version> version() = 0;

    // rpc Tx(stream Cursor) returns (stream Pair);
    virtual Task<std::unique_ptr<Transaction>> begin_transaction() = 0;

    // rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
    virtual Task<void> state_changes(const StateChangeOptions& options, StateChangeConsumer consumer) = 0;
};

}  // namespace silkworm::db::kv::api
