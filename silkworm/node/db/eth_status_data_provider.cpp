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

#include "eth_status_data_provider.hpp"

#include <stdexcept>

#include <gsl/util>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/store/access_layer.hpp>
#include <silkworm/sentry/eth/protocol.hpp>

namespace silkworm::db {

void EthStatusDataProvider::HeadInfo::debug_log() const {
    log::Debug(
        "EthStatusDataProvider::HeadInfo",
        {
            "head hash",
            hash.to_hex(),

            "head total difficulty",
            intx::to_string(total_difficulty),

            "head block num",
            std::to_string(block_num),
        });
}

EthStatusDataProvider::HeadInfo EthStatusDataProvider::read_head_info(ROTxn& txn) {
    HeadInfo head_info;

    BlockNum head_height = db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey);
    head_info.block_num = head_height;

    auto head_hash = db::read_canonical_hash(txn, head_height);
    if (head_hash) {
        head_info.hash = head_hash.value();
    } else {
        log::Warning("EthStatusDataProvider") << "canonical hash at height " << std::to_string(head_height) << " not found in db";
        return head_info;
    }

    auto head_total_difficulty = db::read_total_difficulty(txn, head_height, *head_hash);
    if (head_total_difficulty) {
        head_info.total_difficulty = head_total_difficulty.value();
    } else {
        log::Warning("EthStatusDataProvider") << "total difficulty of canonical hash at height " << std::to_string(head_height) << " not found in db";
    }

    return head_info;
}

EthStatusDataProvider::StatusData EthStatusDataProvider::make_status_data(
    HeadInfo head_info,
    uint8_t eth_version,
    const ChainConfig& chain_config) {
    auto fork_numbers = chain_config.distinct_fork_numbers();
    auto fork_times = chain_config.distinct_fork_times();
    auto best_block_hash = Bytes{ByteView{head_info.hash}};
    auto genesis_hash = ByteView{chain_config.genesis_hash.value()};

    silkworm::sentry::eth::StatusMessage status_message = {
        eth_version,
        chain_config.chain_id,
        head_info.total_difficulty,
        best_block_hash,
        Bytes{genesis_hash},
        silkworm::sentry::eth::ForkId(genesis_hash, fork_numbers, fork_times, head_info.block_num),
    };

    silkworm::sentry::eth::StatusData status_data = {
        std::move(fork_numbers),
        std::move(fork_times),
        head_info.block_num,
        std::move(status_message),
    };

    return status_data;
}

EthStatusDataProvider::StatusData EthStatusDataProvider::get_status_data(uint8_t eth_version) {
    if (eth_version != silkworm::sentry::eth::Protocol::kVersion) {
        throw std::runtime_error("EthStatusDataProvider::get_status_data: unsupported eth version " + std::to_string(eth_version));
    }

    auto txn = db_access_.start_ro_tx();
    [[maybe_unused]] auto _ = gsl::finally([&txn] { txn.abort(); });

    auto head_info = read_head_info(txn);
    head_info.debug_log();

    return make_status_data(head_info, eth_version, chain_config_);
}

EthStatusDataProvider::StatusDataProvider EthStatusDataProvider::to_factory_function() {
    return [provider = *this](uint8_t eth_version) mutable -> Task<StatusData> {
        co_return provider.get_status_data(eth_version);
    };
}

}  // namespace silkworm::db
