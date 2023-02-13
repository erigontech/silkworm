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
#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/attestation.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/beacon_block_header.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {

struct ProposerSlashing : public ssz::Container {
    SignedBeaconBlockHeader signed_header_1, signed_header_2;

    static constexpr std::size_t ssz_size = 416;
    [[nodiscard]] std::size_t get_ssz_size() const override { return ssz_size; }
    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&signed_header_1, &signed_header_2}); }
    [[nodiscard]] BytesVector serialize() const override { return serialize_({&signed_header_1, &signed_header_2}); }
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

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&attestation_1, &attestation_2}); }
    [[nodiscard]] BytesVector serialize() const override { return serialize_({&attestation_1, &attestation_2}); }
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

}  // namespace eth
