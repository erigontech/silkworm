/*  bytes.hpp
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

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstring>
#include <numeric>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

#include <silkworm/lightclient/ssz/ssz_container.hpp>
#include <silkworm/lightclient/ssz/helpers/bytes_to_int.hpp>
// #include "yaml-cpp/yaml.h"

namespace eth {

class Byte : public ssz::Container {
  private:
    uint8_t value;

  public:
    constexpr Byte() : value{} {};
    constexpr ~Byte() = default;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const override {
        std::vector<std::uint8_t> ret{value};
        return ret;
    }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        if (std::distance(it, end) != 1) return false;
        value = *it;
        return true;
    }

    explicit operator std::vector<std::uint8_t>() {
        std::vector<std::uint8_t> ret{value};
        return ret;
    }

    static constexpr std::size_t ssz_size = 1;
    static constexpr std::size_t size() { return 1; }
    [[nodiscard]] constexpr std::size_t get_ssz_size() const override { return 1; }

    /*YAML::Node encode() const override {
        auto str = this->to_string();
        return YAML::convert<std::string>::encode(str);
    }
    bool decode(const YAML::Node &node) override {
        std::string str;
        if (!YAML::convert<std::string>::decode(node, str)) return false;
        this->from_string(str);
        return true;
    }*/
};

template <std::size_t N>
class Bytes : public ssz::Container {
   private:
    std::array<std::uint8_t, N> m_arr;

    // cppcheck-suppress unusedPrivateFunction
    static constexpr auto bytes_from_int(std::integral auto value) {
        std::array<std::uint8_t, N> ret{};
        // TODO(canepat) std::bit_cast is not found in Apple Clang 14
        // auto as_bytes = std::bit_cast<std::array<std::uint8_t, sizeof(value)>>(value);
        std::span as_bytes{reinterpret_cast<uint8_t*>(&value), sizeof(value)};
        if constexpr (std::endian::native == std::endian::big)
            std::reverse_copy(as_bytes.begin(), as_bytes.end(), ret.begin());
        else
            std::copy(as_bytes.begin(), as_bytes.end(), ret.begin());
        return ret;
    }

    static constexpr auto chars_to_byte(std::string_view const &c) -> std::uint8_t {
        return std::uint8_t(helpers::strhex2int(c));
    }

    static constexpr auto bytes_from_str(const std::string_view &str) -> std::array<std::uint8_t, N> {
        if (!str.starts_with("0x")) throw std::invalid_argument("string not prepended with 0x");

        if (str.size() > 2 * N + 2) throw std::out_of_range("integer larger than bytes size");

        std::array<std::uint8_t, N> ret_arr{};
        for (size_t i = 2; i < str.size(); i += 2) ret_arr[i / 2 - 1] = chars_to_byte(str.substr(i, 2));
        return ret_arr;
    }

   public:
    constexpr Bytes() : m_arr{} {};
    explicit constexpr Bytes(const std::string_view &hex) : m_arr{bytes_from_str(hex)} {};
    explicit constexpr Bytes(std::string_view &&hex) : m_arr{bytes_from_str(std::forward<std::string_view>(hex))} {};
    explicit constexpr Bytes(const std::integral auto value) requires(sizeof(value) <= N)
        : m_arr{bytes_from_int(value)} {};
    explicit constexpr Bytes(std::array<std::uint8_t, N> arr) : m_arr{arr} {};
    constexpr ~Bytes() = default;

    std::vector<std::uint8_t> serialize() const override {
        std::vector<std::uint8_t> ret(m_arr.cbegin(), m_arr.cend());
        return ret;
    }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        if (std::distance(it, end) != N) return false;
        std::copy(it, end, m_arr.begin());
        return true;
    }

    operator std::vector<std::uint8_t>() {
        std::vector<std::uint8_t> ret(m_arr.begin(), m_arr.end());
        return ret;
    }

    constexpr std::uint8_t *data() noexcept { return m_arr.data(); }

    const std::array<std::uint8_t, N> &to_array() const { return m_arr; }

    /*std::string to_string() const {
        return helpers::bytes_to_string(m_arr);
    };*/

    void from_string(const std::string &hex) { m_arr = bytes_from_str(hex); }

    // clang-format off
    template <typename T> requires(std::unsigned_integral<T> && sizeof(T) == N)
    T to_integer_little_endian() const {
    auto ptr = reinterpret_cast<const T *>(m_arr.data()); // NOLINT
    return *ptr;
    }
    // clang-format on
    constexpr std::uint8_t &operator[](std::size_t index) { return m_arr[index]; }

    constexpr std::uint8_t operator[](std::size_t index) const { return m_arr[index]; }

    void operator^=(Bytes<N> const &b) {
        for (int i = 0; i < N; i++) m_arr[i] ^= b[i];
    }

    template <std::size_t M>
    constexpr bool operator==(Bytes<M> const &r) const {
        if (N != M) return false;
        return m_arr == r.to_array();
    }

    constexpr bool operator==(std::vector<std::uint8_t> const &r) const {
        if (N != r.size()) return false;
        for (int i = 0; i < N; ++i)
            if (m_arr[i] != r[i]) return false;
        return true;
    }

    template <std::size_t M>
    Bytes<N + M> operator+(Bytes<M> const &r) const {
        std::array<std::uint8_t, N + M> ret;
        std::copy(m_arr.cbegin(), m_arr.cend(), ret.begin());
        std::copy(r.to_array().cbegin(), r.to_array().cend(), ret.begin() + N);
        return Bytes<N + M>(ret);
    }

    static constexpr std::size_t ssz_size = N;
    static constexpr std::size_t size() { return N; }
    constexpr std::size_t get_ssz_size() const override { return N; }

    constexpr typename std::array<std::uint8_t, N>::iterator begin() noexcept { return m_arr.begin(); }

    constexpr typename std::array<std::uint8_t, N>::const_iterator cbegin() const noexcept { return m_arr.cbegin(); }

    constexpr typename std::array<std::uint8_t, N>::iterator end() noexcept { return m_arr.end(); }

    constexpr typename std::array<std::uint8_t, N>::const_iterator cend() const noexcept { return m_arr.cend(); }

    /*YAML::Node encode() const override {
        auto str = this->to_string();
        return YAML::convert<std::string>::encode(str);
    }
    bool decode(const YAML::Node &node) override {
        std::string str;
        if (!YAML::convert<std::string>::decode(node, str)) return false;
        this->from_string(str);
        return true;
    }*/
};

using Bytes1 = Bytes<1>;
using Bytes4 = Bytes<4>;    // NOLINT
using Bytes8 = Bytes<8>;    // NOLINT
using Bytes20 = Bytes<20>;  // NOLINT
using Bytes32 = Bytes<32>;  // NOLINT
using Bytes48 = Bytes<48>;  // NOLINT
using Bytes96 = Bytes<96>;  // NOLINT
using Bytes256 = Bytes<256>;  // NOLINT
using BytesVector = std::vector<std::uint8_t>;

using Hash32 = Bytes32;
using Root = Bytes32;
using Version = Bytes4;
using DomainType = Bytes4;
using ForkDigest = Bytes4;
using Domain = Bytes32;
using BLSPubkey = Bytes48;
using BLSSignature = Bytes96;
using Eth1Address = Bytes20;
using Participation = Byte;

}  // namespace eth
