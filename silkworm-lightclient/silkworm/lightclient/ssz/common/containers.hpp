/*  containers.hpp
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
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>

#include "../common/slot.hpp"
#include "../ssz/hashtree.hpp"
#include "../ssz/ssz.hpp"
#include "../ssz/ssz_container.hpp"
// #include "yaml-cpp/yaml.h"

namespace eth

{
template <class T>
concept BasicObject = std::unsigned_integral<T> || std::is_same_v<T, Slot>;

template <class T, std::size_t N>
class VectorFixedSizedParts : public ssz::Container {
   private:
    std::array<T, N> m_arr;

   protected:
    std::vector<ssz::Chunk> hash_tree_x() const requires BasicObject<T> { return ssz::Container::hash_tree(); }

    std::vector<ssz::Chunk> hash_tree_x() const requires(!BasicObject<T>) {
        std::vector<ssz::Chunk> chunks{};
        chunks.reserve(m_arr.size());
        for (auto &part : m_arr) chunks.push_back(part.hash_tree_root());
        // return early if only one chunk
        if (N == 1) return chunks;

        ssz::HashTree ht{chunks};
        return ht.hash_tree();
    }

    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_x(); }

   public:
    static constexpr std::size_t ssz_size = N * T::ssz_size;
    std::size_t get_ssz_size() const override { return ssz_size; }

    static std::size_t size(void) { return N; }

    constexpr typename std::array<T, N>::iterator begin() noexcept { return m_arr.begin(); }

    constexpr typename std::array<T, N>::const_iterator cbegin() const noexcept { return m_arr.cbegin(); }

    constexpr typename std::array<T, N>::iterator end() noexcept { return m_arr.end(); }

    constexpr typename std::array<T, N>::const_iterator cend() const noexcept { return m_arr.cend(); }

    BytesVector serialize() const override {
        BytesVector ret;
        for (auto part : m_arr) {
            auto part_ssz = part.serialize();
            ret.insert(ret.end(), part_ssz.begin(), part_ssz.end());
        }
        return ret;
    }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        if (std::distance(it, end) != ssz_size) return false;

        for (size_t i = 0; i < N; ++i)
            if (!m_arr[i].deserialize(it + long(i * T::ssz_size), it + long((i + 1) * T::ssz_size))) return false;
        return true;
    }

    /*YAML::Node encode() const override { return YAML::convert<std::array<T, N>>::encode(m_arr); }
    bool decode(const YAML::Node &node) override { return YAML::convert<std::array<T, N>>::decode(node, m_arr); }*/
};

template <class T>
class ListFixedSizedParts : public ssz::Container {
   private:
    std::vector<T> m_arr;
    std::size_t limit_;

   protected:
    std::vector<ssz::Chunk> hash_tree_x() const requires BasicObject<T> {
        auto ser = this->serialize();
        auto limit = (limit_ * T::ssz_size + constants::BYTES_PER_CHUNK - 1) / constants::BYTES_PER_CHUNK;
        ssz::HashTree ht{ser, limit};
        ht.mix_in(m_arr.size());
        return ht.hash_tree();
    }
    std::vector<ssz::Chunk> hash_tree_x() const requires(!BasicObject<T>) {
        std::vector<ssz::Chunk> chunks{};
        chunks.reserve(m_arr.size());
        for (auto &part : m_arr) chunks.push_back(part.hash_tree_root());
        if (chunks.empty()) {
            ssz::Chunk chunk{};
            chunks.push_back(chunk);
        }
        ssz::HashTree ht{chunks, limit_};
        ht.mix_in(m_arr.size());
        return ht.hash_tree();
    }
    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_x(); }

   public:
    ListFixedSizedParts(std::size_t limit = 0) : limit_{limit} {};
    std::size_t size(void) const { return m_arr.size(); }

    constexpr typename std::vector<T>::iterator begin() noexcept { return m_arr.begin(); }
    constexpr typename std::vector<T>::const_iterator cbegin() const noexcept { return m_arr.cbegin(); }
    constexpr typename std::vector<T>::iterator end() noexcept { return m_arr.end(); }
    constexpr typename std::vector<T>::const_iterator cend() const noexcept { return m_arr.cend(); }
    std::vector<T>& data() { return m_arr; }

    void limit(std::size_t limit) { limit_ = limit; }

    BytesVector serialize() const override {
        BytesVector ret;
        for (auto part : m_arr) {
            auto part_ssz = part.serialize();
            ret.insert(ret.end(), part_ssz.begin(), part_ssz.end());
        }
        return ret;
    }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        m_arr.clear();
        if (std::distance(it, end) % long(T::ssz_size)) return false;

        for (auto i = it; i != end; i += long(T::ssz_size)) {
            T obj;
            if (!obj.deserialize(i, i + T::ssz_size)) return false;
            m_arr.push_back(obj);
        }
        return true;
    }
    /*YAML::Node encode() const override { return YAML::convert<std::vector<T>>::encode(m_arr); }
    bool decode(const YAML::Node &node) override { return YAML::convert<std::vector<T>>::decode(node, m_arr); }*/
};

template <class T>
class ListVariableSizedParts : public ssz::Container {
   private:
    std::vector<T> m_arr;
    std::size_t limit_;

   public:
    ListVariableSizedParts(std::size_t limit = 0) : limit_{limit} {};

    std::size_t size(void) const { return m_arr.size(); }
    constexpr typename std::vector<T>::iterator begin() noexcept { return m_arr.begin(); }
    constexpr typename std::vector<T>::const_iterator cbegin() const noexcept { return m_arr.cbegin(); }
    constexpr typename std::vector<T>::iterator end() noexcept { return m_arr.end(); }
    constexpr typename std::vector<T>::const_iterator cend() const noexcept { return m_arr.cend(); }
    std::vector<ssz::Chunk> hash_tree() const override {
        std::vector<ssz::Chunk> chunks{};
        chunks.reserve(m_arr.size());
        std::transform(m_arr.begin(), m_arr.end(), std::back_inserter(chunks),
                       [](const T &part) { return part.hash_tree_root(); });
        if (chunks.empty()) {
            ssz::Chunk chunk{};
            chunks.push_back(chunk);
        }
        ssz::HashTree ht{chunks, limit_};
        ht.mix_in(m_arr.size());
        return ht.hash_tree();
    }
    BytesVector serialize() const override {
        BytesVector offsets, ret;
        std::uint32_t offset = size() * constants::BYTES_PER_LENGTH_OFFSET;
        for (auto part : m_arr) {
            auto offset_ssz = Bytes4(offset).serialize();
            offsets.insert(offsets.end(), offset_ssz.begin(), offset_ssz.end());

            auto part_ssz = part.serialize();
            offset += part_ssz.size();
            ret.insert(ret.end(), part_ssz.begin(), part_ssz.end());
        }
        if (offsets.size()) ret.insert(ret.begin(), offsets.begin(), offsets.end());
        return ret;
    }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        m_arr.clear();
        if (it == end)  // empty list
            return true;
        if (std::distance(it, end) < constants::BYTES_PER_LENGTH_OFFSET) return false;
        auto start = it;
        auto first_offset = helpers::to_integer_little_endian<std::uint32_t>(&*it);
        if (first_offset < constants::BYTES_PER_LENGTH_OFFSET) return false;
        if (std::distance(start, end) < first_offset) return false;
        auto last_offset = first_offset;
        it += constants::BYTES_PER_LENGTH_OFFSET;

        while (it != start + first_offset) {
            if (std::distance(start, it) + constants::BYTES_PER_LENGTH_OFFSET > first_offset) return false;

            auto current_offset = helpers::to_integer_little_endian<std::uint32_t>(&*it);
            if (current_offset < last_offset) return false;
            if (std::distance(start, end) < current_offset) return false;
            T obj;
            if (!obj.deserialize(start + last_offset, start + current_offset)) return false;
            m_arr.push_back(obj);
            last_offset = current_offset;
            it += constants::BYTES_PER_LENGTH_OFFSET;
        }
        T obj;
        if (!obj.deserialize(start + last_offset, end)) return false;
        m_arr.push_back(obj);
        return true;
    }

    /*YAML::Node encode() const override { return YAML::convert<std::vector<T>>::encode(m_arr); }
    bool decode(const YAML::Node &node) override { return YAML::convert<std::vector<T>>::decode(node, m_arr); }*/
};

struct Fork : public ssz::Container {
    Version previous_version, current_version;
    Epoch epoch;

    static constexpr std::size_t ssz_size = 16;
    std::size_t get_ssz_size() const override { return ssz_size; }

    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&previous_version, &current_version, &epoch});
    }

    BytesVector serialize() const override { return serialize_({&previous_version, &current_version, &epoch}); }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&previous_version, &current_version, &epoch});
    }

    bool operator==(const Fork &) const = default;

    /*YAML::Node encode() const override {
        return encode_(
            {{"previous_version", &previous_version}, {"current_version", &current_version}, {"epoch", &epoch}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(
            node, {{"previous_version", &previous_version}, {"current_version", &current_version}, {"epoch", &epoch}});
    }*/
};

struct ForkData : public ssz::Container {
    Version current_version;
    Root genesis_validators_root;

    static constexpr std::size_t ssz_size = 36;
    std::size_t get_ssz_size() const override { return ssz_size; }

    std::vector<ssz::Chunk> hash_tree() const override {
        return hash_tree_({&current_version, &genesis_validators_root});
    }

    BytesVector serialize() const override { return serialize_({&current_version, &genesis_validators_root}); }

    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&current_version, &genesis_validators_root});
    }

    /*YAML::Node encode() const override {
        return encode_({{"current_version", &current_version}, {"genesis_validators_root", &genesis_validators_root}});
    }

    bool decode(const YAML::Node &node) override {
        return decode_(node,
                       {{"current_version", &current_version}, {"genesis_validators_root", &genesis_validators_root}});
    }*/
};

struct Checkpoint : public ssz::Container {
    Epoch epoch;
    Root root;

    explicit Checkpoint() : epoch{}, root{} {}
    Checkpoint(Epoch _epoch, Root _root) : epoch(_epoch), root(_root) {}

    static constexpr std::size_t ssz_size = 40;
    std::size_t get_ssz_size() const override { return ssz_size; }
    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&epoch, &root}); }
    BytesVector serialize() const override { return serialize_({&epoch, &root}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&epoch, &root});
    }

    /*YAML::Node encode() const override { return encode_({{"epoch", &epoch}, {"root", &root}}); }

    bool decode(const YAML::Node &node) override { return decode_(node, {{"epoch", &epoch}, {"root", &root}}); }*/
};

struct SigningData : public ssz::Container {
    Root object_root;
    Domain domain;

    static constexpr std::size_t ssz_size = 64;
    std::size_t get_ssz_size() const override { return ssz_size; }

    std::vector<ssz::Chunk> hash_tree() const override { return hash_tree_({&object_root, &domain}); }
    BytesVector serialize() const override { return serialize_({&object_root, &domain}); }
    bool deserialize(ssz::SSZIterator it, ssz::SSZIterator end) override {
        return deserialize_(it, end, {&object_root, &domain});
    }

    /*YAML::Node encode() const override { return encode_({{"object_root", &object_root}, {"domain", &domain}}); }

    bool decode(const YAML::Node &node) override {
        return decode_(node, {{"object_root", &object_root}, {"domain", &domain}});
    }*/
};

}  // namespace eth
