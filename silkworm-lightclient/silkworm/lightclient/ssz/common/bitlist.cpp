/*  bitlist.cpp
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

#include "bitlist.hpp"

#include <bit>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <silkworm/lightclient/ssz/hashtree.hpp>
#include <silkworm/lightclient/ssz/helpers/bytes_to_int.hpp>

namespace eth {

std::vector<ssz::Chunk> Bitlist::hash_tree() const {
    using namespace constants;
    std::vector<std::uint8_t> ret((m_arr.size() + BITS_PER_BYTE - 1) / BITS_PER_BYTE, 0);
    for (std::size_t i = 0; i < m_arr.size(); ++i) ret[i / constants::BITS_PER_BYTE] |= m_arr[i] << (i % BITS_PER_BYTE);
    auto limit = (limit_ + BITS_PER_BYTE * BYTES_PER_CHUNK - 1) / (BITS_PER_BYTE * BYTES_PER_CHUNK);
    ssz::HashTree ht{ret, limit};
    ht.mix_in(m_arr.size());
    return ht.hash_tree();
}

std::vector<std::uint8_t> Bitlist::serialize() const {
    std::vector<std::uint8_t> ret(m_arr.size() / constants::BITS_PER_BYTE + 1, 0);
    for (std::size_t i = 0; i < m_arr.size(); ++i)
        ret[i / constants::BITS_PER_BYTE] |= m_arr[i] << (i % constants::BITS_PER_BYTE);
    ret.back() |= 1 << (m_arr.size() % constants::BITS_PER_BYTE);
    return ret;
}

bool Bitlist::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    auto last = end;
    --last;
    int msb = std::countl_zero(*last);
    m_arr.clear();

    for (auto i = it; i != last; ++i)
        for (auto j = 0; j < int(constants::BITS_PER_BYTE); ++j) m_arr.push_back((*i >> j) & 1);

    for (auto i = 0; i < int(constants::BITS_PER_BYTE) - 1 - msb; ++i) m_arr.push_back((*last >> i) & 1);
    return true;
}

// Does not check for errors, assumes strings is 0x valid hex bytes! In
// particular even # of chars
void Bitlist::from_hexstring(const std::string& str) {
    if (!str.starts_with("0x")) throw std::invalid_argument("string not prepended with 0x");
    if (str.length() % 2 != 0) throw std::invalid_argument("string of odd length");

    std::uint8_t buffer = 0;
    std::vector<std::uint8_t> hex;
    for (std::size_t offset = 2; offset < str.length(); offset += 2) {
        buffer = (helpers::hextoint(str[offset]) << 4) + helpers::hextoint(str[offset + 1]);
        hex.push_back(buffer);
    }
    deserialize(hex.begin(), hex.end());
}

std::string Bitlist::to_string() const {
    std::stringstream os;
    std::ios_base::fmtflags save = std::cout.flags();
    auto serial = this->serialize();
    os << "0x";
    for (auto i = serial.cbegin(); i != serial.cend(); ++i) os << std::setfill('0') << std::setw(2) << std::hex << *i;
    std::cout.flags(save);
    return os.str();
}

/*YAML::Node Bitlist::encode() const {
    auto str = this->to_string();
    return YAML::convert<std::string>::encode(str);
}
bool Bitlist::decode(const YAML::Node& node) {
    std::string str;
    if (!YAML::convert<std::string>::decode(node, str)) return false;
    this->from_hexstring(str);
    return true;
}*/

}  // namespace eth
