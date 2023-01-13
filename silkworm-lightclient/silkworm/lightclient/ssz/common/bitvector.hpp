/*  bitvector.hpp
 *
 *  This file is part of sszpp.
 *  sszpp is C++ implementation of the "Simple Serialize" specification.
 *  https://github.com/ethereum/eth2.0-specs/tree/dev/ssz
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

#include <array>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <silkworm/lightclient/ssz/chunk.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/common/bytes.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {

template <unsigned N>
class Bitvector : public ssz::Container {
   private:
    std::array<bool, N> m_arr;

   public:
    static constexpr std::size_t ssz_size = (N + constants::BITS_PER_BYTE - 1) / constants::BITS_PER_BYTE;
    [[nodiscard]] std::size_t get_ssz_size() const override { return ssz_size; }

    Bitvector() = default;
    explicit constexpr Bitvector(std::array<bool, N> vec) : m_arr{vec} {};

    void from_hexstring(const std::string &str) {
        if (!str.starts_with("0x")) throw std::invalid_argument("string not prepended with 0x");
        if (str.length() % 2 != 0) throw std::invalid_argument("string of odd length");

        std::uint8_t buffer = 0;
        std::vector<std::uint8_t> hex;
        for (std::size_t offset = 2; offset < str.length(); offset += 2) {
            buffer = (helpers::hextoint(str[offset]) << 4) + helpers::hextoint(str[offset + 1]);
            hex.push_back(buffer);
        }
        m_arr.fill(0);
        for (int i = 0; i < hex.size(); ++i)
            for (int j = 0; j < int(constants::BITS_PER_BYTE) && constants::BITS_PER_BYTE * i + j < N; ++j)
                m_arr[constants::BITS_PER_BYTE * i + j] = ((hex[i] >> j) & 1);
    }

    std::string to_string() const {
        std::stringstream os;
        std::ios_base::fmtflags save = std::cout.flags();
        auto serial = this->serialize();
        os << "0x";
        for (auto i = serial.cbegin(); i != serial.cend(); ++i)
            os << std::setfill('0') << std::setw(2) << std::hex << *i;
        std::cout.flags(save);
        return os.str();
    };

    friend std::ostream &operator<<(std::ostream &os, const Bitvector<N> &m_bits) {
        for (auto const &b : m_bits.m_arr) os << b;
        return os;
    };
    std::vector<std::uint8_t> serialize() const override {
        Bytes<(N + constants::BITS_PER_BYTE - 1) / constants::BITS_PER_BYTE> ret{};
        for (size_t i = 0; i < N; ++i) ret[i / constants::BITS_PER_BYTE] |= m_arr[i] << (i % constants::BITS_PER_BYTE);
        return ret;
    }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        if (std::distance(it, end) != (N + constants::BITS_PER_BYTE - 1) / constants::BITS_PER_BYTE) return false;
        for (auto i = it; i != end; ++i)
            for (int j = 0; j < int(constants::BITS_PER_BYTE) && constants::BITS_PER_BYTE * std::distance(it, i) + j < N;
                 ++j)
                m_arr[size_t(constants::BITS_PER_BYTE * std::distance(it, i) + j)] = *i & (1 << j);
        return true;
    }
    bool operator==(const Bitvector &) const = default;

    /*YAML::Node encode() const override {
        auto str = this->to_string();
        return YAML::convert<std::string>::encode(str);
    }
    bool decode(const YAML::Node &node) override {
        std::string str;
        if (!YAML::convert<std::string>::decode(node, str)) return false;
        this->from_hexstring(str);
        return true;
    }*/
};

}  // namespace eth
