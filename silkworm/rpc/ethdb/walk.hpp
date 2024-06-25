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

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::rpc::ethdb {

using Walker = std::function<bool(Bytes&, Bytes&)>;

Task<void> walk(db::kv::api::Transaction& tx, const std::string& table, ByteView start_key, uint32_t fixed_bits, Walker w);

Task<void> for_prefix(db::kv::api::Transaction& tx, const std::string& table, ByteView prefix, Walker w);

}  // namespace silkworm::rpc::ethdb
