/*  boolean.hpp
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

#include <cstdint>

#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/common/bytes.hpp>
#include <silkworm/lightclient/ssz/helpers/bytes_to_int.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {
class Boolean : public ssz::Container {
   private:
    bool value_;

   public:
    Boolean(bool s = false) : value_{s} {};
    operator bool() const { return value_; };
    operator bool &() { return value_; }
    operator Bytes1() const { return Bytes1{std::uint8_t(value_)}; }
    std::vector<std::uint8_t> serialize() const override { return Bytes1(value_).serialize(); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        if (std::distance(it, end) != 1) return false;
        auto muint = helpers::to_integer_little_endian<std::uint8_t>(&*it);
        if (muint > 1) return false;
        value_ = bool(muint);
        return true;
    }

    bool operator==(const Boolean &) const = default;

    static constexpr std::size_t ssz_size = 1;
    std::size_t get_ssz_size() const override { return ssz_size; }

    /*YAML::Node encode() const override { return YAML::convert<bool>::encode(value_); }
    bool decode(const YAML::Node &node) override { return YAML::convert<bool>::decode(node, value_); }*/
};
}  // namespace eth
