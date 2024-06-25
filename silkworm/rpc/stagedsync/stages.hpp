/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::rpc::stages {

const Bytes kHeaders = string_to_bytes(db::stages::kHeadersKey);
const Bytes kExecution = string_to_bytes(db::stages::kExecutionKey);
const Bytes kFinish = string_to_bytes(db::stages::kFinishKey);

Task<BlockNum> get_sync_stage_progress(db::kv::api::Transaction& tx, const Bytes& stage_key);

}  // namespace silkworm::rpc::stages
