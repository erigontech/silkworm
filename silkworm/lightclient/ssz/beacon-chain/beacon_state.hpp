/*  beacon_state.hpp
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

#include <silkworm/lightclient/ssz/chunk.hpp>
#include <silkworm/lightclient/ssz/constants.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/beacon_block.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/execution_header.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/sync_committee.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/validator.hpp>
#include <silkworm/lightclient/ssz/common/bitlist.hpp>
#include <silkworm/lightclient/ssz/common/bitvector.hpp>

namespace eth {
class BeaconStatePhase0 : public ssz::Container {
  private:
    UnixTime genesis_time_;
    Root genesis_validators_root_;
    Slot slot_;
    Fork fork_;
    BeaconBlockHeader latest_block_header_;
    VectorFixedSizedParts<Root, constants::SLOTS_PER_HISTORICAL_ROOT> block_roots_, state_roots_;
    ListFixedSizedParts<Root> historical_roots_{constants::HISTORICAL_ROOTS_LIMIT};
    Eth1Data eth1_data_;
    ListFixedSizedParts<Eth1Data> eth1_data_votes_{constants::EPOCHS_PER_ETH1_VOTING_PERIOD *
                                                   constants::kSlotsPerEpoch};
    DepositIndex eth1_deposit_index_;
    ListFixedSizedParts<Validator> validators_{constants::VALIDATOR_REGISTRY_LIMIT};
    ListFixedSizedParts<Gwei> balances_{constants::VALIDATOR_REGISTRY_LIMIT};
    VectorFixedSizedParts<Bytes32, constants::EPOCHS_PER_HISTORICAL_VECTOR> randao_mixes_;
    VectorFixedSizedParts<Gwei, constants::EPOCHS_PER_SLASHINGS_VECTOR> slashings_;
    ListVariableSizedParts<PendingAttestation> previous_epoch_attestations_{constants::MAX_ATTESTATIONS *
                                                                            constants::kSlotsPerEpoch},
        current_epoch_attestations_{constants::MAX_ATTESTATIONS * constants::kSlotsPerEpoch};
    Bitvector<constants::JUSTIFICATION_BITS_LENGTH> justification_bits_;
    Checkpoint previous_justified_checkpoint_, current_justified_checkpoint_, finalized_checkpoint_;

  public:
    BeaconStatePhase0() = default;

    [[nodiscard]] constexpr UnixTime genesis_time() const { return genesis_time_; }
    constexpr const Root &genesis_validators_root() const { return genesis_validators_root_; }
    constexpr Slot slot() const { return slot_; }
    constexpr const auto& fork() const { return fork_; }
    constexpr const auto& latest_block_header() const { return latest_block_header_; }
    constexpr const auto& block_roots() const { return block_roots_; }
    constexpr const auto& state_roots() const { return state_roots_; }
    constexpr const auto& historical_roots() const { return historical_roots_; }
    constexpr const auto& eth1_data() const { return eth1_data_; }
    constexpr const auto& eth1_data_votes() const { return eth1_data_votes_; }
    constexpr const auto& eth1_deposit_index() const { return eth1_deposit_index_; }
    constexpr const auto& validators() const { return validators_; }
    constexpr const auto& balances() const { return balances_; }
    constexpr const auto& slashings() const { return slashings_; }
    constexpr const auto& randao_mixes() const { return randao_mixes_; }
    constexpr const auto& previous_epoch_attestations() const { return previous_epoch_attestations_; }
    constexpr const auto& current_epoch_attestations() const { return current_epoch_attestations_; }
    constexpr const auto& justification_bits() const { return justification_bits_; }
    constexpr const Checkpoint &previous_justified_checkpoint() const { return previous_justified_checkpoint_; }
    constexpr const Checkpoint &current_justified_checkpoint() const { return current_justified_checkpoint_; }
    constexpr const Checkpoint &finalized_checkpoint() const { return finalized_checkpoint_; }

    /*
                void genesis_time(UnixTime);
                void genesis_validators_root(Root);
                void slot(Slot);
                void fork(Fork);
                void latest_block_header(BeaconBlockHeader);
                void block_roots(<Root>);
                void state_roots(std::vector<Root>);
                void historical_roots(std::vector<Root>);
                void eth1_data(Eth1Data);
                void eth1_data_votes(std::vector<Eth1Data>);
                void eth1_deposit_index(DepositIndex);
                void validators(std::vector<Validator>);
                void balances(std::vector<Gwei>);
                void slashings(std::vector<Gwei>);
                void randao_mixes(std::vector<Bytes32>);
                void previous_epoch_attestations(std::vector<PendingAttestation>);
                void current_epoch_attestations(std::vector<PendingAttestation>);
                void justification_bits(std::vector<bool>);
                void previous_justified_checkpoint(Checkpoint);
                void current_justified_checkpoint(Checkpoint);
                void finalized_checkpoint(Checkpoint);
                */

    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&genesis_time_,
                           &genesis_validators_root_,
                           &slot_,
                           &fork_,
                           &latest_block_header_,
                           &block_roots_,
                           &state_roots_,
                           &historical_roots_,
                           &eth1_data_,
                           &eth1_data_votes_,
                           &eth1_deposit_index_,
                           &validators_,
                           &balances_,
                           &randao_mixes_,
                           &slashings_,
                           &previous_epoch_attestations_,
                           &current_epoch_attestations_,
                           &justification_bits_,
                           &previous_justified_checkpoint_,
                           &current_justified_checkpoint_,
                           &finalized_checkpoint_});
    }
    BytesVector serialize() const override {
        return serialize_({&genesis_time_,
                           &genesis_validators_root_,
                           &slot_,
                           &fork_,
                           &latest_block_header_,
                           &block_roots_,
                           &state_roots_,
                           &historical_roots_,
                           &eth1_data_,
                           &eth1_data_votes_,
                           &eth1_deposit_index_,
                           &validators_,
                           &balances_,
                           &randao_mixes_,
                           &slashings_,
                           &previous_epoch_attestations_,
                           &current_epoch_attestations_,
                           &justification_bits_,
                           &previous_justified_checkpoint_,
                           &current_justified_checkpoint_,
                           &finalized_checkpoint_});
    }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end,
                            {&genesis_time_,
                             &genesis_validators_root_,
                             &slot_,
                             &fork_,
                             &latest_block_header_,
                             &block_roots_,
                             &state_roots_,
                             &historical_roots_,
                             &eth1_data_,
                             &eth1_data_votes_,
                             &eth1_deposit_index_,
                             &validators_,
                             &balances_,
                             &randao_mixes_,
                             &slashings_,
                             &previous_epoch_attestations_,
                             &current_epoch_attestations_,
                             &justification_bits_,
                             &previous_justified_checkpoint_,
                             &current_justified_checkpoint_,
                             &finalized_checkpoint_});
    }

    bool operator==(const BeaconStatePhase0 &) const = default;

    /*YAML::Node encode() const override {
        return encode_({{"genesis_time", &genesis_time_},
                        {"genesis_validators_root", &genesis_validators_root_},
                        {"slot", &slot_},
                        {"fork", &fork_},
                        {"latest_block_header", &latest_block_header_},
                        {"block_roots", &block_roots_},
                        {"state_roots", &state_roots_},
                        {"historical_roots", &historical_roots_},
                        {"eth1_data", &eth1_data_},
                        {"eth1_data_votes", &eth1_data_votes_},
                        {"eth1_deposit_index", &eth1_deposit_index_},
                        {"validators", &validators_},
                        {"balances", &balances_},
                        {"randao_mixes", &randao_mixes_},
                        {"slashings", &slashings_},
                        {"previous_epoch_attestations", &previous_epoch_attestations_},
                        {"current_epoch_attestations", &current_epoch_attestations_},
                        {"justification_bits", &justification_bits_},
                        {"previous_justified_checkpoint", &previous_justified_checkpoint_},
                        {"current_justified_checkpoint", &current_justified_checkpoint_},
                        {"finalized_checkpoint", &finalized_checkpoint_}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"genesis_time", &genesis_time_},
                              {"genesis_validators_root", &genesis_validators_root_},
                              {"slot", &slot_},
                              {"fork", &fork_},
                              {"latest_block_header", &latest_block_header_},
                              {"block_roots", &block_roots_},
                              {"state_roots", &state_roots_},
                              {"historical_roots", &historical_roots_},
                              {"eth1_data", &eth1_data_},
                              {"eth1_data_votes", &eth1_data_votes_},
                              {"eth1_deposit_index", &eth1_deposit_index_},
                              {"validators", &validators_},
                              {"balances", &balances_},
                              {"randao_mixes", &randao_mixes_},
                              {"slashings", &slashings_},
                              {"previous_epoch_attestations", &previous_epoch_attestations_},
                              {"current_epoch_attestations", &current_epoch_attestations_},
                              {"justification_bits", &justification_bits_},
                              {"previous_justified_checkpoint", &previous_justified_checkpoint_},
                              {"current_justified_checkpoint", &current_justified_checkpoint_},
                              {"finalized_checkpoint", &finalized_checkpoint_}});
    }*/
};

class BeaconStateBellatrix : public ssz::Container {
  private:
    UnixTime genesis_time_;
    Root genesis_validators_root_;
    Slot slot_;
    Fork fork_;
    BeaconBlockHeader latest_block_header_;
    VectorFixedSizedParts<Root, constants::SLOTS_PER_HISTORICAL_ROOT> block_roots_, state_roots_;
    ListFixedSizedParts<Root> historical_roots_{constants::HISTORICAL_ROOTS_LIMIT};
    Eth1Data eth1_data_;
    ListFixedSizedParts<Eth1Data> eth1_data_votes_{constants::EPOCHS_PER_ETH1_VOTING_PERIOD *
                                                   constants::kSlotsPerEpoch};
    DepositIndex eth1_deposit_index_;
    ListFixedSizedParts<Validator> validators_{constants::VALIDATOR_REGISTRY_LIMIT};
    ListFixedSizedParts<Gwei> balances_{constants::BALANCE_REGISTRY_LIMIT};
    VectorFixedSizedParts<Bytes32, constants::EPOCHS_PER_HISTORICAL_VECTOR> randao_mixes_;
    VectorFixedSizedParts<Gwei, constants::EPOCHS_PER_SLASHINGS_VECTOR> slashings_;
    ListFixedSizedParts<Participation> previous_epoch_participations_{constants::PARTICIPATION_REGISTRY_LIMIT};
    ListFixedSizedParts<Participation> current_epoch_participations_{constants::PARTICIPATION_REGISTRY_LIMIT};
    Bitvector<constants::JUSTIFICATION_BITS_LENGTH> justification_bits_;
    Checkpoint previous_justified_checkpoint_, current_justified_checkpoint_, finalized_checkpoint_;
    ListFixedSizedParts<Score> inactivity_scores_{constants::INACTIVITY_SCORE_REGISTRY_LIMIT};
    SyncCommittee current_sync_committee_;
    SyncCommittee next_sync_committee_;
    ExecutionHeader latest_execution_payload_header_;

  public:
    BeaconStateBellatrix() = default;
    constexpr UnixTime genesis_time() const { return genesis_time_; }
    constexpr const Root &genesis_validators_root() const { return genesis_validators_root_; }
    constexpr Slot slot() const { return slot_; }
    constexpr const Fork &fork() const { return fork_; }
    constexpr const BeaconBlockHeader &latest_block_header() const { return latest_block_header_; }
    constexpr const auto &block_roots() const { return block_roots_; }
    constexpr const auto &state_roots() const { return state_roots_; }
    constexpr const auto &historical_roots() const { return historical_roots_; }
    constexpr const Eth1Data &eth1_data() const { return eth1_data_; }
    constexpr const auto &eth1_data_votes() const { return eth1_data_votes_; }
    constexpr const auto &eth1_deposit_index() const { return eth1_deposit_index_; }
    constexpr const auto &validators() const { return validators_; }
    constexpr const auto &balances() const { return balances_; }
    constexpr const auto &slashings() const { return slashings_; }
    constexpr const auto &randao_mixes() const { return randao_mixes_; }
    constexpr const auto &previous_epoch_participations() const { return previous_epoch_participations_; }
    constexpr const auto &current_epoch_participations() const { return current_epoch_participations_; }
    constexpr const auto &justification_bits() const { return justification_bits_; }
    constexpr const Checkpoint& previous_justified_checkpoint() const { return previous_justified_checkpoint_; }
    constexpr const Checkpoint& current_justified_checkpoint() const { return current_justified_checkpoint_; }
    constexpr const Checkpoint& finalized_checkpoint() const { return finalized_checkpoint_; }
    [[nodiscard]] const auto& inactivity_scores() const { return inactivity_scores_; }
    [[nodiscard]] const auto& current_sync_committee() const { return current_sync_committee_; }
    [[nodiscard]] const auto& next_sync_committee() const { return next_sync_committee_; }
    [[nodiscard]] constexpr auto& latest_execution_payload_header() const { return latest_execution_payload_header_; }

    /*
                void genesis_time(UnixTime);
                void genesis_validators_root(Root);
                void slot(Slot);
                void fork(Fork);
                void latest_block_header(BeaconBlockHeader);
                void block_roots(<Root>);
                void state_roots(std::vector<Root>);
                void historical_roots(std::vector<Root>);
                void eth1_data(Eth1Data);
                void eth1_data_votes(std::vector<Eth1Data>);
                void eth1_deposit_index(DepositIndex);
                void validators(std::vector<Validator>);
                void balances(std::vector<Gwei>);
                void slashings(std::vector<Gwei>);
                void randao_mixes(std::vector<Bytes32>);
                void previous_epoch_attestations(std::vector<PendingAttestation>);
                void current_epoch_attestations(std::vector<PendingAttestation>);
                void justification_bits(std::vector<bool>);
                void previous_justified_checkpoint(Checkpoint);
                void current_justified_checkpoint(Checkpoint);
                void finalized_checkpoint(Checkpoint);
                */

    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&genesis_time_,
                           &genesis_validators_root_,
                           &slot_,
                           &fork_,
                           &latest_block_header_,
                           &block_roots_,
                           &state_roots_,
                           &historical_roots_,
                           &eth1_data_,
                           &eth1_data_votes_,
                           &eth1_deposit_index_,
                           &validators_,
                           &balances_,
                           &randao_mixes_,
                           &slashings_,
                           &previous_epoch_participations_,
                           &current_epoch_participations_,
                           &justification_bits_,
                           &previous_justified_checkpoint_,
                           &current_justified_checkpoint_,
                           &finalized_checkpoint_,
                           &inactivity_scores_,
                           &current_sync_committee_,
                           &next_sync_committee_,
                           &latest_execution_payload_header_});
    }
    BytesVector serialize() const override {
        return serialize_({&genesis_time_,
                           &genesis_validators_root_,
                           &slot_,
                           &fork_,
                           &latest_block_header_,
                           &block_roots_,
                           &state_roots_,
                           &historical_roots_,
                           &eth1_data_,
                           &eth1_data_votes_,
                           &eth1_deposit_index_,
                           &validators_,
                           &balances_,
                           &randao_mixes_,
                           &slashings_,
                           &previous_epoch_participations_,
                           &current_epoch_participations_,
                           &justification_bits_,
                           &previous_justified_checkpoint_,
                           &current_justified_checkpoint_,
                           &finalized_checkpoint_,
                           &inactivity_scores_,
                           &current_sync_committee_,
                           &next_sync_committee_,
                           &latest_execution_payload_header_});
    }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end,
                            {&genesis_time_,
                             &genesis_validators_root_,
                             &slot_,
                             &fork_,
                             &latest_block_header_,
                             &block_roots_,
                             &state_roots_,
                             &historical_roots_,
                             &eth1_data_,
                             &eth1_data_votes_,
                             &eth1_deposit_index_,
                             &validators_,
                             &balances_,
                             &randao_mixes_,
                             &slashings_,
                             &previous_epoch_participations_,
                             &current_epoch_participations_,
                             &justification_bits_,
                             &previous_justified_checkpoint_,
                             &current_justified_checkpoint_,
                             &finalized_checkpoint_,
                             &inactivity_scores_,
                             &current_sync_committee_,
                             &next_sync_committee_,
                             &latest_execution_payload_header_});
    }

    bool operator==(const BeaconStateBellatrix &) const = default;

    /*YAML::Node encode() const override {
        return encode_({{"genesis_time", &genesis_time_},
                        {"genesis_validators_root", &genesis_validators_root_},
                        {"slot", &slot_},
                        {"fork", &fork_},
                        {"latest_block_header", &latest_block_header_},
                        {"block_roots", &block_roots_},
                        {"state_roots", &state_roots_},
                        {"historical_roots", &historical_roots_},
                        {"eth1_data", &eth1_data_},
                        {"eth1_data_votes", &eth1_data_votes_},
                        {"eth1_deposit_index", &eth1_deposit_index_},
                        {"validators", &validators_},
                        {"balances", &balances_},
                        {"randao_mixes", &randao_mixes_},
                        {"slashings", &slashings_},
                        {"previous_epoch_participations", &previous_epoch_participations_},
                        {"current_epoch_participations", &current_epoch_participations_},
                        {"justification_bits", &justification_bits_},
                        {"previous_justified_checkpoint", &previous_justified_checkpoint_},
                        {"current_justified_checkpoint", &current_justified_checkpoint_},
                        {"finalized_checkpoint", &finalized_checkpoint_},
                        {"inactivity_scores", &inactivity_scores_},
                        {"current_sync_committee", &current_sync_committee_},
                        {"next_sync_committee", &next_sync_committee_}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"genesis_time", &genesis_time_},
                              {"genesis_validators_root", &genesis_validators_root_},
                              {"slot", &slot_},
                              {"fork", &fork_},
                              {"latest_block_header", &latest_block_header_},
                              {"block_roots", &block_roots_},
                              {"state_roots", &state_roots_},
                              {"historical_roots", &historical_roots_},
                              {"eth1_data", &eth1_data_},
                              {"eth1_data_votes", &eth1_data_votes_},
                              {"eth1_deposit_index", &eth1_deposit_index_},
                              {"validators", &validators_},
                              {"balances", &balances_},
                              {"randao_mixes", &randao_mixes_},
                              {"slashings", &slashings_},
                              {"previous_epoch_participations", &previous_epoch_participations_},
                              {"current_epoch_participations", &current_epoch_participations_},
                              {"justification_bits", &justification_bits_},
                              {"previous_justified_checkpoint", &previous_justified_checkpoint_},
                              {"current_justified_checkpoint", &current_justified_checkpoint_},
                              {"finalized_checkpoint", &finalized_checkpoint_},
                              {"inactivity_scores", &inactivity_scores_},
                              {"current_sync_committee", &current_sync_committee_},
                              {"next_sync_committee", &next_sync_committee_}});
    }*/
};

using BeaconState = BeaconStateBellatrix;

}  // namespace eth
