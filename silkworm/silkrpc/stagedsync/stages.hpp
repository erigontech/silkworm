/*
   Copyright 2020 The Silkrpc Authors

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

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/node/db/stages.hpp>

#include <silkworm/silkrpc/core/rawdb/accessors.hpp>

namespace silkrpc::stages {

const silkworm::Bytes kHeaders = silkworm::bytes_of_string(silkworm::db::stages::kHeadersKey);
const silkworm::Bytes kExecution = silkworm::bytes_of_string(silkworm::db::stages::kExecutionKey);
const silkworm::Bytes kFinish = silkworm::bytes_of_string(silkworm::db::stages::kFinishKey);

boost::asio::awaitable<uint64_t> get_sync_stage_progress(const core::rawdb::DatabaseReader& database, const silkworm::Bytes& stake_key);

} // namespace silkrpc::stages

