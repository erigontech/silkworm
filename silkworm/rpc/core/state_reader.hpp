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

#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>

namespace silkworm::rpc {

class StateReader {
  public:
    explicit StateReader(const core::rawdb::DatabaseReader& db_reader) : db_reader_(db_reader) {}

    StateReader(const StateReader&) = delete;
    StateReader& operator=(const StateReader&) = delete;

    [[nodiscard]] Task<std::optional<silkworm::Account>> read_account(const evmc::address& address, BlockNum block_number) const;

    [[nodiscard]] Task<evmc::bytes32> read_storage(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& location_hash,
        BlockNum block_number) const;

    [[nodiscard]] Task<std::optional<silkworm::Bytes>> read_code(const evmc::bytes32& code_hash) const;

    [[nodiscard]] Task<std::optional<silkworm::Bytes>> read_historical_account(const evmc::address& address, BlockNum block_number) const;

    [[nodiscard]] Task<std::optional<silkworm::Bytes>> read_historical_storage(const evmc::address& address, uint64_t incarnation,
                                                                               const evmc::bytes32& location_hash, BlockNum block_number) const;

  private:
    const core::rawdb::DatabaseReader& db_reader_;
};

}  // namespace silkworm::rpc
