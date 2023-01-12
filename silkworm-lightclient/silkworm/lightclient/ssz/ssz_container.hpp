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
/*  ssz_container.hpp
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

#include <cstddef>
#include <string>
#include <vector>

#include <silkworm/lightclient/ssz/ssz/ssz.hpp>
// #include "yaml-cpp/yaml.h"

namespace ssz {
class Container;
using Part = std::pair<std::string, Container *>;
using ConstPart = std::pair<std::string, const Container *>;
using SSZIterator = std::vector<std::uint8_t>::const_iterator;

class Container {
   protected:
    static std::vector<std::uint8_t> serialize_(const std::vector<const Container *> &);
    static bool deserialize_(SSZIterator it, SSZIterator end, const std::vector<Container *> &);
    /*static YAML::Node encode_(const std::vector<ConstPart> &parts);
    static bool decode_(const YAML::Node &node, std::vector<Part> parts);*/
    static std::vector<Chunk> hash_tree_(const std::vector<const Container *> &);
    [[nodiscard]] virtual std::vector<Chunk> hash_tree() const;

   public:
    virtual ~Container() = default;
    Container() = default;
    Container(Container &&) = default;
    Container(const Container &) = default;
    Container &operator=(Container &&) = default;
    Container &operator=(const Container &) = default;

    [[nodiscard]] virtual std::size_t get_ssz_size() const { return 0; }
    [[nodiscard]] virtual std::vector<std::uint8_t> serialize() const = 0;
    virtual bool deserialize(SSZIterator it, SSZIterator end) = 0;

    [[nodiscard]] Chunk hash_tree_root() const { return this->hash_tree().back(); }

    /*virtual YAML::Node encode() const = 0;
    virtual bool decode(const YAML::Node &node) = 0;*/
    bool operator==(const Container &) const { return true; }
};

}  // namespace ssz

// clang-format off
/*template <class T>
requires std::is_base_of<ssz::Container, T>::value
struct YAML::convert<T> {
  static YAML::Node encode(const ssz::Container &c) { return c.encode(); }
  static bool decode(const YAML::Node &node, ssz::Container &c) {
    return c.decode(node);
  }
};*/
// clang-format on
