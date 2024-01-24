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

#include <functional>

#include <silkworm/infra/concurrency/task.hpp>

#include <intx/intx.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

namespace silkworm::db {

class EthStatusDataProvider {
    struct HeadInfo {
        BlockNum block_num{0};
        Hash hash;
        intx::uint256 total_difficulty;

        void debug_log() const;
    };

  public:
    EthStatusDataProvider(
        db::ROAccess db_access,
        const ChainConfig& chain_config)
        : db_access_(std::move(db_access)),
          chain_config_(chain_config) {}

    using StatusData = silkworm::sentry::eth::StatusData;
    [[nodiscard]] StatusData get_status_data(uint8_t eth_version);

    using StatusDataProvider = std::function<Task<StatusData>(uint8_t eth_version)>;
    [[nodiscard]] StatusDataProvider to_factory_function();

  private:
    static HeadInfo read_head_info(ROTxn& txn);
    static StatusData make_status_data(
        HeadInfo head_info,
        uint8_t eth_version,
        const ChainConfig& chain_config);

    db::ROAccess db_access_;
    const ChainConfig& chain_config_;
};

}  // namespace silkworm::db
