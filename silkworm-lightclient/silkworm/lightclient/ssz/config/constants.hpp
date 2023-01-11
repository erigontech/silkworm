/*  constants.hpp
 *
 *  This file is part of Mammon.
 *  mammon is a greedy and selfish ETH consensus client.
 *
 *  Copyright (c) 2021 - Reimundo Heluani (potuz) potuz@potuz.net
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "../common/slot.hpp"

namespace constants {
constexpr auto GENESIS_SLOT = eth::Slot{0};
constexpr auto GENESIS_EPOCH = eth::Epoch{0};
constexpr auto FAR_FUTURE_EPOCH = eth::Epoch{0xffffffffffffffffull};
constexpr auto BASE_REWARDS_PER_EPOCH = 0x4ull;
constexpr auto DEPOSIT_CONTRACT_TREE_DEPTH = 0X20ull;
constexpr auto JUSTIFICATION_BITS_LENGTH = 0x4ull;
constexpr auto MAX_EFFECTIVE_BALANCE = eth::Gwei{32000000000};
constexpr auto MIN_DEPOSIT_AMOUNT = eth::Gwei{1000000000};
constexpr auto EFFECTIVE_BALANCE_INCREMENT = eth::Gwei{1000000000};
constexpr uint MIN_ATTESTATION_INCLUSION_DELAY = 1;

constexpr std::uint64_t MIN_GENESIS_ACTIVE_VALIDATOR_COUNT = 16384;
constexpr std::uint64_t MIN_GENESIS_TIME = 1606824000;
const eth::Version GENESIS_FORK_VERSION{0x00000000};
constexpr std::uint64_t GENESIS_DELAY = 604800;

// ALTAIR_FORK_VERSION: 0x01000001
// ALTAIR_FORK_EPOCH: 18446744073709551615
// MERGE_FORK_VERSION: 0x02000001
// MERGE_FORK_EPOCH: 18446744073709551615
// SHARDING_FORK_VERSION: 0x03000001
// SHARDING_FORK_EPOCH: 18446744073709551615
// MIN_ANCHOR_POW_BLOCK_DIFFICULTY: 4294967296

constexpr std::uint64_t SECONDS_PER_SLOT = 12;
constexpr std::uint64_t SECONDS_PER_ETH1_BLOCK = 14;
constexpr std::uint64_t MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256;
constexpr std::uint64_t SHARD_COMMITTEE_PERIOD = 256;
constexpr std::uint64_t ETH1_FOLLOW_DISTANCE = 2048;

constexpr eth::Gwei EJECTION_BALANCE = 16000000000;
constexpr std::uint64_t MIN_PER_EPOCH_CHURN_LIMIT = 4;
constexpr std::uint64_t CHURN_LIMIT_QUOTIENT = 65536;

constexpr int DEPOSIT_CHAIN_ID = 1;
constexpr int DEPOSIT_NETWORK_ID = 1;
constexpr eth::Eth1Address DEPOSIT_CONTRACT_ADDRESS{
    "0x00000000219ab540356cBB839Cbe05303d7705Fa"};

constexpr auto TEST_VECTORS_PATH = "@CMAKE_SOURCE_DIR@/eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/";
constexpr auto TEST_VECTORS_GENERAL_PATH = "@CMAKE_SOURCE_DIR@/eth2.0-spec-tests/tests/general/phase0/ssz_generic/";

constexpr uint MAX_COMMITTEES_PER_SLOT = 64;
constexpr uint TARGET_COMMITTEE_SIZE = 128;
constexpr uint MAX_VALIDATORS_PER_COMMITTEE = 2048;
constexpr uint SHUFFLE_ROUND_COUNT = 90;
constexpr uint HYSTERESIS_QUOTIENT = 4;
constexpr uint HYSTERESIS_DOWNWARD_MULTIPLIER = 1;
constexpr uint HYSTERESIS_UPWARD_MULTIPLIER = 5;
constexpr uint SAFE_SLOTS_TO_UPDATE_JUSTIFIED = 8;
constexpr uint SLOTS_PER_EPOCH = 32;
constexpr uint MIN_SEED_LOOKAHEAD = 1;
constexpr uint MAX_SEED_LOOKAHEAD = 4;
constexpr uint EPOCHS_PER_ETH1_VOTING_PERIOD = 64;
constexpr uint SLOTS_PER_HISTORICAL_ROOT = 8192;
constexpr uint MIN_EPOCHS_TO_INACTIVITY_PENALTY = 4;
constexpr uint EPOCHS_PER_HISTORICAL_VECTOR = 65536;
constexpr uint EPOCHS_PER_SLASHINGS_VECTOR = 8192;
constexpr uint64_t HISTORICAL_ROOTS_LIMIT = 16777216;
constexpr uint64_t VALIDATOR_REGISTRY_LIMIT = 1099511627776;
constexpr uint64_t BALANCE_REGISTRY_LIMIT = 1099511627776;
constexpr uint BASE_REWARD_FACTOR = 64;
constexpr uint WHISTLEBLOWER_REWARD_QUOTIENT = 512;
constexpr uint PROPOSER_REWARD_QUOTIENT = 8;
constexpr uint64_t INACTIVITY_PENALTY_QUOTIENT = 67108864;
constexpr uint MIN_SLASHING_PENALTY_QUOTIENT = 128;
constexpr uint PROPORTIONAL_SLASHING_MULTIPLIER = 1;
constexpr uint MAX_PROPOSER_SLASHINGS = 16;
constexpr uint MAX_ATTESTER_SLASHINGS = 2;
constexpr uint MAX_ATTESTATIONS = 128;
constexpr uint MAX_DEPOSITS = 16;
constexpr uint MAX_VOLUNTARY_EXITS = 16;

constexpr uint64_t MAX_BYTES_PER_TRANSACTION = 1048576;

constexpr uint64_t PARTICIPATION_REGISTRY_LIMIT = 1099511627776;
constexpr uint64_t INACTIVITY_SCORE_REGISTRY_LIMIT = 1099511627776;
constexpr uint MAX_PUB_KEYS_PER_COMMITTEE = 512;
constexpr uint MAX_LOGS_BLOOM = 256;

} // namespace constants
