// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "status_data.hpp"

#include <algorithm>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/sentry/eth/fork_id.hpp>

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;
using namespace silkworm::rpc;

eth::StatusData status_data_from_proto(const proto::StatusData& data, uint8_t eth_version) {
    Bytes genesis_hash = bytes_from_h256(data.fork_data().genesis());

    const auto& block_num_forks = data.fork_data().height_forks();
    std::vector<BlockNum> fork_block_nums;
    fork_block_nums.resize(static_cast<size_t>(block_num_forks.size()));
    std::copy(block_num_forks.cbegin(), block_num_forks.cend(), fork_block_nums.begin());

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
        uint256_from_h256(data.total_difficulty()),
        bytes_from_h256(data.best_hash()),
        genesis_hash,
        eth::ForkId{genesis_hash, fork_block_nums, fork_block_times, data.max_block_height()},
    };

    return eth::StatusData{
        std::move(fork_block_nums),
        std::move(fork_block_times),
        data.max_block_height(),
        std::move(message),
    };
}

static proto::Forks make_proto_forks(ByteView genesis_hash, const std::vector<BlockNum>& fork_block_nums,
                                     const std::vector<BlockTime>& fork_block_times) {
    proto::Forks forks;
    forks.mutable_genesis()->CopyFrom(*h256_from_bytes(genesis_hash));

    for (auto block_num : fork_block_nums) {
        forks.add_height_forks(block_num);
    }

    for (auto block_time : fork_block_times) {
        forks.add_time_forks(block_time);
    }

    return forks;
}

proto::StatusData proto_status_data_from_status_data(const eth::StatusData& data) {
    proto::StatusData result;
    result.set_network_id(data.message.network_id);
    result.mutable_total_difficulty()->CopyFrom(*h256_from_uint256(data.message.total_difficulty));
    result.mutable_best_hash()->CopyFrom(*h256_from_bytes(data.message.best_block_hash));
    result.mutable_fork_data()->CopyFrom(make_proto_forks(data.message.genesis_hash, data.fork_block_nums, data.fork_block_times));
    result.set_max_block_height(data.head_block_num);

    // TODO: set max_block_time
    // result.set_max_block_time()

    // TODO: set passive_peers
    // result.set_passive_peers()

    return result;
}

}  // namespace silkworm::sentry::grpc::interfaces
