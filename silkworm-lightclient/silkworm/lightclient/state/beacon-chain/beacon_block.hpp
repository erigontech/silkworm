/*  beacon_block.hpp
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

#include <utility>

#include "attestation.hpp"
#include "deposits.hpp"
#include "eth1data.hpp"
#include "silkworm/lightclient/ssz/common/slot.hpp"
// #include "include/config.hpp"
#include "silkworm/lightclient/ssz/ssz/ssz.hpp"
#include "silkworm/lightclient/ssz/ssz/ssz_container.hpp"
// #include "yaml-cpp/yaml.h"

namespace eth {
struct BeaconBlockHeader : public ssz::Container {
    Slot slot;
    ValidatorIndex proposer_index;
    Root parent_root, state_root, body_root;

    static constexpr std::size_t ssz_size = 112;
    std::size_t get_ssz_size() const override { return ssz_size; }
    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&slot, &proposer_index, &parent_root, &state_root, &body_root});
    }
    BytesVector serialize() const override {
        return serialize_({&slot, &proposer_index, &parent_root, &state_root, &body_root});
    }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&slot, &proposer_index, &parent_root, &state_root, &body_root});
    }

    bool operator==(const BeaconBlockHeader &) const = default;

    /*YAML::Node encode() const override {
        return encode_({{"slot", &slot},
                        {"proposer_index", &proposer_index},
                        {"parent_root", &parent_root},
                        {"state_root", &state_root},
                        {"body_root", &body_root}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"slot", &slot},
                              {"proposer_index", &proposer_index},
                              {"parent_root", &parent_root},
                              {"state_root", &state_root},
                              {"body_root", &body_root}});
    }*/
};


struct VoluntaryExit : public ssz::Container {
    Epoch epoch;
    ValidatorIndex validator_index;

    static constexpr std::size_t ssz_size = 16;
    std::size_t get_ssz_size() const override { return ssz_size; }

    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&epoch, &validator_index}); }
    BytesVector serialize() const override { return serialize_({&epoch, &validator_index}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&epoch, &validator_index});
    }
    bool operator==(const VoluntaryExit &) const = default;

    /*YAML::Node encode() const override { return encode_({{"epoch", &epoch}, {"validator_index", &validator_index}}); }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"epoch", &epoch}, {"validator_index", &validator_index}});
    }*/
};

struct SignedVoluntaryExit : public ssz::Container {
    VoluntaryExit message;
    BLSSignature signature;

    static constexpr std::size_t ssz_size = 112;
    std::size_t get_ssz_size() const override { return ssz_size; }
    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&message, &signature}); }
    BytesVector serialize() const override { return serialize_({&message, &signature}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&message, &signature});
    }
    bool operator==(const SignedVoluntaryExit &) const = default;

    /*YAML::Node encode() const override { return encode_({{"message", &message}, {"signature", &signature}}); }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"message", &message}, {"signature", &signature}});
    }*/
};

struct ProposerSlashing;
struct AttesterSlashing;

class BeaconBlockBody : public ssz::Container {
   private:
    BLSSignature randao_reveal_;
    Eth1Data eth1_data_;
    Bytes32 graffiti_;

    ListFixedSizedParts<ProposerSlashing> proposer_slashings_{constants::MAX_PROPOSER_SLASHINGS};
    ListVariableSizedParts<AttesterSlashing> attester_slashings_{constants::MAX_ATTESTER_SLASHINGS};
    ListVariableSizedParts<Attestation> attestations_{constants::MAX_ATTESTATIONS};
    ListFixedSizedParts<Deposit> deposits_{constants::MAX_DEPOSITS};
    ListFixedSizedParts<SignedVoluntaryExit> voluntary_exits_{constants::MAX_VOLUNTARY_EXITS};

   public:
    constexpr BLSSignature const &randao_reveal() const { return randao_reveal_; }
    constexpr Eth1Data const &eth1_data() const { return eth1_data_; }
    constexpr Bytes32 const &graffiti() const { return graffiti_; }
    constexpr ListFixedSizedParts<ProposerSlashing> const &proposer_slashings() const { return proposer_slashings_; }
    constexpr ListVariableSizedParts<AttesterSlashing> const &attester_slashings() const { return attester_slashings_; }
    constexpr ListVariableSizedParts<Attestation> const &attestations() const { return attestations_; }
    constexpr ListFixedSizedParts<Deposit> const &deposits() const { return deposits_; }
    constexpr ListFixedSizedParts<SignedVoluntaryExit> const &voluntary_exits() const { return voluntary_exits_; }

    void randao_reveal(BLSSignature &&s);
    void eth1_data(Eth1Data &&);
    void graffiti(Bytes32 &&);
    void proposer_slashings(ListFixedSizedParts<ProposerSlashing> &&);
    void attester_slashings(ListVariableSizedParts<AttesterSlashing> &&);
    void attestations(ListVariableSizedParts<Attestation> &&);
    void deposits(ListFixedSizedParts<Deposit> &&);
    void voluntary_exits(ListFixedSizedParts<SignedVoluntaryExit> &&);

    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&randao_reveal_, &eth1_data_, &graffiti_, &proposer_slashings_, &attester_slashings_,
                           &attestations_, &deposits_, &voluntary_exits_});
    }

    BytesVector serialize() const override {
        return serialize_({&randao_reveal_, &eth1_data_, &graffiti_, &proposer_slashings_, &attester_slashings_,
                           &attestations_, &deposits_, &voluntary_exits_});
    }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end,
                            {&randao_reveal_, &eth1_data_, &graffiti_, &proposer_slashings_, &attester_slashings_,
                             &attestations_, &deposits_, &voluntary_exits_});
    }

    /*YAML::Node encode() const override {
        return encode_({{"randao_reveal", &randao_reveal_},
                        {"eth1_data", &eth1_data_},
                        {"graffiti", &graffiti_},
                        {"proposer_slashings", &proposer_slashings_},
                        {"attester_slashings", &attester_slashings_},
                        {"attestations", &attestations_},
                        {"deposits", &deposits_},
                        {"voluntary_exits", &voluntary_exits_}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"randao_reveal", &randao_reveal_},
                              {"eth1_data", &eth1_data_},
                              {"graffiti", &graffiti_},
                              {"proposer_slashings", &proposer_slashings_},
                              {"attester_slashings", &attester_slashings_},
                              {"attestations", &attestations_},
                              {"deposits", &deposits_},
                              {"voluntary_exits", &voluntary_exits_}});
    }*/
};

class BeaconBlock : public ssz::Container {
    Slot slot_;
    ValidatorIndex proposer_index_;
    Root parent_root_, state_root_;
    BeaconBlockBody body_;

   public:
    Slot slot() const { return slot_; }
    ValidatorIndex proposer_index() const { return proposer_index_; }
    const Root &parent_root() const { return parent_root_; }
    const Root &state_root() const { return state_root_; }
    const BeaconBlockBody &body() const { return body_; }
    void slot(Slot &&);
    void proposer_index(ValidatorIndex &&);
    void parent_root(Root &&);
    void state_root(Root &&);
    void body(BeaconBlockBody &&);

    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&slot_, &proposer_index_, &parent_root_, &state_root_, &body_});
    }

    BytesVector serialize() const override {
        return serialize_({&slot_, &proposer_index_, &parent_root_, &state_root_, &body_});
    }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&slot_, &proposer_index_, &parent_root_, &state_root_, &body_});
    }

    /*YAML::Node encode() const override {
        return encode_({{"slot", &slot_},
                        {"proposer_index", &proposer_index_},
                        {"parent_root", &parent_root_},
                        {"state_root", &state_root_},
                        {"body", &body_}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"slot", &slot_},
                              {"proposer_index", &proposer_index_},
                              {"parent_root", &parent_root_},
                              {"state_root", &state_root_},
                              {"body", &body_}});
    }*/
};

struct SignedBeaconBlockHeader : public ssz::Container {
    BeaconBlockHeader message;
    BLSSignature signature;

    static constexpr std::size_t ssz_size = 208;
    std::size_t get_ssz_size() const override { return ssz_size; }
    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&message, &signature}); }
    BytesVector serialize() const override { return serialize_({&message, &signature}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&message, &signature});
    }

    /*YAML::Node encode() const override { return encode_({{"message", &message}, {"signature", &signature}}); }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"message", &message}, {"signature", &signature}});
    }*/
};

struct ProposerSlashing : public ssz::Container {
    SignedBeaconBlockHeader signed_header_1, signed_header_2;

    static constexpr std::size_t ssz_size = 416;
    std::size_t get_ssz_size() const override { return ssz_size; }
    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&signed_header_1, &signed_header_2}); }
    BytesVector serialize() const override { return serialize_({&signed_header_1, &signed_header_2}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&signed_header_1, &signed_header_2});
    }

    /*YAML::Node encode() const override {
        return encode_({{"signed_header_1", &signed_header_1}, {"signed_header_2", &signed_header_2}});
    }
    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"signed_header_1", &signed_header_1}, {"signed_header_2", &signed_header_2}});
    }*/
};

struct AttesterSlashing : public ssz::Container {
    IndexedAttestation attestation_1, attestation_2;

    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&attestation_1, &attestation_2}); }
    BytesVector serialize() const override { return serialize_({&attestation_1, &attestation_2}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&attestation_1, &attestation_2});
    }

    /*YAML::Node encode() const override {
        return encode_({{"attestation_1", &attestation_1}, {"attestation_2", &attestation_2}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"attestation_1", &attestation_1}, {"attestation_2", &attestation_2}});
    }*/
};

struct SignedBeaconBlock : public ssz::Container {
    BeaconBlock message;
    BLSSignature signature;

    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&message, &signature}); }
    BytesVector serialize() const override { return serialize_({&message, &signature}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&message, &signature});
    }

    /*YAML::Node encode() const override { return encode_({{"message", &message}, {"signature", &signature}}); }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"message", &message}, {"signature", &signature}});
    }*/
};

}  // namespace eth
