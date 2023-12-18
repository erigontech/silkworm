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
#include <silkworm/node/db/stages.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>

namespace silkworm::rpc::stages {

const silkworm::Bytes kHeaders = silkworm::bytes_of_string(silkworm::db::stages::kHeadersKey);
const silkworm::Bytes kExecution = silkworm::bytes_of_string(silkworm::db::stages::kExecutionKey);
const silkworm::Bytes kFinish = silkworm::bytes_of_string(silkworm::db::stages::kFinishKey);

Task<BlockNum> get_sync_stage_progress(const core::rawdb::DatabaseReader& db_reader, const silkworm::Bytes& stage_key);

}  // namespace silkworm::rpc::stages
