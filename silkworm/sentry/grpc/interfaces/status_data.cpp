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

#include "status_data.hpp"

#include <algorithm>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/grpc/interfaces/types.hpp>
#include <silkworm/sentry/eth/fork_id.hpp>

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;

eth::StatusData status_data_from_proto(const proto::StatusData& data, uint8_t eth_version) {
    Bytes genesis_hash{hash_from_H256(data.fork_data().genesis())};

    const auto& height_forks = data.fork_data().height_forks();
    std::vector<BlockNum> fork_block_numbers;
    fork_block_numbers.resize(static_cast<size_t>(height_forks.size()));
    std::copy(height_forks.cbegin(), height_forks.cend(), fork_block_numbers.begin());

    const auto& time_forks = data.fork_data().time_forks();
    std::vector<BlockTime> fork_block_times;
    fork_block_times.resize(static_cast<size_t>(time_forks.size()));
    std::copy(time_forks.cbegin(), time_forks.cend(), fork_block_times.begin());

    // TODO: handle max_block_time
    // data.max_block_time()

    // TODO: handle passive_peers
    // data.passive_peers()

    auto message = eth::StatusMessage{
        eth_version,
        data.network_id(),
        uint256_from_H256(data.total_difficulty()),
        Bytes{hash_from_H256(data.best_hash())},
        genesis_hash,
        eth::ForkId{genesis_hash, fork_block_numbers, fork_block_times, data.max_block_height()},
    };

    return eth::StatusData{
        std::move(fork_block_numbers),
        std::move(fork_block_times),
        data.max_block_height(),
        std::move(message),
    };
}

static proto::Forks make_proto_forks(ByteView genesis_hash, const std::vector<BlockNum>& fork_block_numbers,
                                     const std::vector<BlockTime>& fork_block_times) {
    proto::Forks forks;
    forks.mutable_genesis()->CopyFrom(*H256_from_bytes(genesis_hash));

    for (auto block_number : fork_block_numbers) {
        forks.add_height_forks(block_number);
    }

    for (auto block_time : fork_block_times) {
        forks.add_time_forks(block_time);
    }

    return forks;
}

proto::StatusData proto_status_data_from_status_data(const eth::StatusData& data) {
    proto::StatusData result;
    result.set_network_id(data.message.network_id);
    result.mutable_total_difficulty()->CopyFrom(*H256_from_uint256(data.message.total_difficulty));
    result.mutable_best_hash()->CopyFrom(*H256_from_hash(Hash{data.message.best_block_hash}));
    result.mutable_fork_data()->CopyFrom(make_proto_forks(data.message.genesis_hash, data.fork_block_numbers, data.fork_block_times));
    result.set_max_block_height(data.head_block_num);

    // TODO: set max_block_time
    // result.set_max_block_time()

    // TODO: set passive_peers
    // result.set_passive_peers()

    return result;
}

}  // namespace silkworm::sentry::grpc::interfaces
