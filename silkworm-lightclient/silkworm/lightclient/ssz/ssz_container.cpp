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

#include "ssz_container.hpp"

#include <array>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/lightclient/ssz/hash_tree.hpp>
#include <silkworm/lightclient/ssz/ssz_codec.hpp>

namespace silkworm::ssz {

/*template <typename T>
static std::uint32_t compute_fixed_length(const std::vector<T*>& parts) {
    std::uint32_t ret{0};
    auto sum_lengths = [&ret](const T *part) {
        if (part->get_ssz_size() == 0) {
            ret += kBytesPerLengthOffset;
        } else {
            ret += std::uint32_t(part->get_ssz_size());
        }
    };
    std::for_each(parts.cbegin(), parts.cend(), sum_lengths);
    return ret;
}

std::vector<std::uint8_t> Container::serialize_(const std::vector<const Container*>& parts) {
    // Check if we are one of the basic types
    if (parts.empty()) return {};

    // Compute the length of the fixed sized parts;
    auto fixed_length = compute_fixed_length(parts);

    // Insert the fixed parts and the offsets
    std::vector<std::uint8_t> ret, variable_part;
    for (auto *part : parts) {
        auto part_ssz = part->serialize();
        if (part->get_ssz_size() == 0) {
            Bytes offset(4, '\0');
            intx::le::unsafe::store<uint32_t>(offset.data(), fixed_length);
            ret.insert(ret.end(), offset.begin(), offset.end());

            fixed_length += std::uint32_t(part_ssz.size());
            variable_part.insert(variable_part.end(), part_ssz.begin(), part_ssz.end());
        } else {
            ret.insert(ret.end(), part_ssz.begin(), part_ssz.end());
        }
    }
    ret.insert(ret.end(), variable_part.begin(), variable_part.end());
    return ret;
}

bool Container::deserialize_(SSZIterator it, SSZIterator end, const std::vector<Container*>& parts) {
    const auto fixed_length = compute_fixed_length(parts);

    auto begin = it;
    // We are hard-coding BYTES_PER_LENGTH_OFFSET = 4 here
    std::uint32_t last_offset = 0;
    Container *last_variable_part = nullptr;

    for (auto *part : parts) {
        int part_size = static_cast<int>(part->get_ssz_size());
        if (part_size) {
            if (std::distance(it, end) < part_size) return false;
            if (!part->deserialize(it, it + part_size))  // NOLINT
                return false;
            it += part_size;  // NOLINT
        } else {
            if (std::distance(it, end) < kBytesPerLengthOffset) return false;
            auto current_offset = endian::load_little_u32(&*it);
            if (std::distance(begin, end) < current_offset) return false;

            if (last_offset) {
                if (current_offset < last_offset) return false;
                if (!last_variable_part->deserialize(begin + last_offset, begin + current_offset)) return false;
            } else if (current_offset != fixed_length)
                return false;

            last_offset = current_offset;
            last_variable_part = part;
            it += kBytesPerLengthOffset;
        }
    }
    if (last_offset)
        if (!last_variable_part->deserialize(begin + last_offset, end)) return false;
    return true;
}*/

/*Hash32Sequence Container::hash_tree() const {
    HashTree hash_tree{serialize()};
    return hash_tree.hash_tree();
}*/

/*Hash32Sequence Container::hash_tree_(const std::vector<const Container*> &parts) {
    // This will throw when accessing hash_tree_root
    if (parts.empty()) return {};

    Hash32Sequence chunks;
    chunks.reserve(parts.size());
    std::transform(
        parts.begin(), parts.end(), std::back_inserter(chunks),
        [](const Container *part) -> auto { return part->hash_tree_root(); });

    HashTree hash_tree{chunks};
    return hash_tree.hash_tree();
}*/

/*bool Container::decode_(const YAML::Node &node, std::vector<Part> parts) {
    return std::all_of(parts.begin(), parts.end(),
                       [&node](Part part) { return part.second->decode(node[part.first]); });
}

YAML::Node Container::encode_(const std::vector<ConstPart> &parts) {
    YAML::Node node;
    for (const auto &part : parts) node[part.first] = part.second->encode();
    return node;
}*/

}  // namespace silkworm::ssz
