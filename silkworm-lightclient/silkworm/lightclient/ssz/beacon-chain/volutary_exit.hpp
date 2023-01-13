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
#include <silkworm/lightclient/ssz/common/slot.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {

struct VoluntaryExit : public ssz::Container {
    Epoch epoch;
    ValidatorIndex validator_index;

    static constexpr std::size_t ssz_size = 16;
    [[nodiscard]] std::size_t get_ssz_size() const override { return ssz_size; }

    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&epoch, &validator_index}); }
    [[nodiscard]] BytesVector serialize() const override { return serialize_({&epoch, &validator_index}); }
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
    [[nodiscard]] std::size_t get_ssz_size() const override { return ssz_size; }
    [[nodiscard]] std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&message, &signature}); }
    [[nodiscard]] BytesVector serialize() const override { return serialize_({&message, &signature}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&message, &signature});
    }
    bool operator==(const SignedVoluntaryExit &) const = default;

    /*YAML::Node encode() const override { return encode_({{"message", &message}, {"signature", &signature}}); }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"message", &message}, {"signature", &signature}});
    }*/
};

}  // namespace eth
