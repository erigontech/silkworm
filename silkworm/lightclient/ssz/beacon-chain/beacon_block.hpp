/*
   Copyright 2022 The Silkworm Authors

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

#include <utility>

#include <silkworm/lightclient/ssz/chunk.hpp>
#include <silkworm/lightclient/ssz/constants.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/attestation.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/deposits.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/eth1data.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/execution_payload.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/slashing.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/sync_aggregate.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/volutary_exit.hpp>
#include <silkworm/lightclient/ssz/common/slot.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {

struct BeaconBlockBody : public ssz::Container {
    BLSSignature randao_reveal;
    Eth1Data eth1_data;
    Bytes32 graffiti;
    ListFixedSizedParts<ProposerSlashing> proposer_slashings{constants::MAX_PROPOSER_SLASHINGS};
    ListVariableSizedParts<AttesterSlashing> attester_slashings{constants::MAX_ATTESTER_SLASHINGS};
    ListVariableSizedParts<Attestation> attestations{constants::MAX_ATTESTATIONS};
    ListFixedSizedParts<Deposit> deposits{constants::MAX_DEPOSITS};
    ListFixedSizedParts<SignedVoluntaryExit> voluntary_exits{constants::MAX_VOLUNTARY_EXITS};
    SyncAggregate sync_aggregate;
    ExecutionPayload execution_payload;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct BeaconBlock : public ssz::Container {
    Slot slot;
    ValidatorIndex proposer_index;
    Root parent_root;
    Root state_root;
    BeaconBlockBody body;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

struct SignedBeaconBlock : public ssz::Container {
    BeaconBlock message;
    BLSSignature signature;

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override;
    [[nodiscard]] BytesVector serialize() const override;
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override;

    /*YAML::Node encode() const override;
    bool decode(const YAML::Node &node) override;*/
};

}  // namespace eth
