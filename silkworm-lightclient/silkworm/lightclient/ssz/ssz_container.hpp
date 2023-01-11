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

#include <array>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>
#include <silkworm/common/encoding_result.hpp>
#include <silkworm/lightclient/util/hash32.hpp>

namespace silkworm::ssz {

class Container;

// using Part = std::pair<std::string, Container*>;
// using ConstPart = std::pair<std::string, const Container*>;
using SSZIterator = std::vector<std::uint8_t>::const_iterator;

class Container {
  public:
    virtual ~Container() = default;
    Container() = default;
    Container(Container&&) = default;
    Container(const Container&) = default;
    Container &operator=(Container&&) = default;
    Container &operator=(const Container&) = default;

    // [[nodiscard]] virtual std::size_t get_ssz_size() const { return 0; }
    // [[nodiscard]] virtual std::vector<std::uint8_t> serialize() const = 0;
    // virtual bool deserialize(SSZIterator it, SSZIterator end) = 0;

    // [[nodiscard]] evmc::bytes32 hash_tree_root() const { return this->hash_tree().back(); }

    /*virtual YAML::Node encode() const = 0;
    virtual bool decode(const YAML::Node &node) = 0;*/
    bool operator==(const Container &) const { return true; }

  protected:
    // static std::vector<std::uint8_t> serialize_(const std::vector<const Container*>& parts);
    // static bool deserialize_(SSZIterator it, SSZIterator end, const std::vector<Container*>& parts);
    /*static YAML::Node encode_(const std::vector<ConstPart> &parts);
    static bool decode_(const YAML::Node &node, std::vector<Part> parts);*/
    static Hash32Sequence hash_tree_(const std::vector<const Container*>& parts);

    // [[nodiscard]] virtual Hash32Sequence hash_tree() const;
};

}  // namespace silkworm::ssz
