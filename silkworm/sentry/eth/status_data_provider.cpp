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

#include "status_data_provider.hpp"

#include <stdexcept>

#include <silkworm/infra/common/log.hpp>

#include "protocol.hpp"

namespace silkworm::sentry::eth {

static void log_head_info(const HeadInfo& info) {
    log::Debug(
        "StatusDataProvider::HeadInfo",
        {
            "head hash",
            info.hash.to_hex(),

            "head total difficulty",
            intx::to_string(info.total_difficulty),

            "head block num",
            std::to_string(info.block_num),
        });
}

StatusDataProvider::StatusData StatusDataProvider::make_status_data(
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

StatusDataProvider::StatusData StatusDataProvider::get_status_data(uint8_t eth_version) {
    if (eth_version != silkworm::sentry::eth::Protocol::kVersion) {
        throw std::runtime_error("StatusDataProvider::get_status_data: unsupported eth version " + std::to_string(eth_version));
    }

    auto head_info = head_info_provider_();
    log_head_info(head_info);

    return make_status_data(head_info, eth_version, chain_config_);
}

StatusDataProvider::StatusDataProviderFactory StatusDataProvider::to_factory_function() {
    return [provider = *this](uint8_t eth_version) mutable -> Task<StatusData> {
        co_return provider.get_status_data(eth_version);
    };
}

}  // namespace silkworm::sentry::eth
