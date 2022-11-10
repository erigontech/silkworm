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

#include "types.hpp"

namespace silkworm::cl {

bool operator==(const Eth1Data& lhs, const Eth1Data& rhs) {
    if (lhs.root != rhs.root) return false;
    if (lhs.deposit_count != rhs.deposit_count) return false;
    if (lhs.block_hash != rhs.block_hash) return false;
    return true;
}

bool operator==(const Checkpoint& lhs, const Checkpoint& rhs) {
    if (lhs.epoch != rhs.epoch) return false;
    if (lhs.root != rhs.root) return false;
    return true;
}

bool operator==(const AttestationData& lhs, const AttestationData& rhs) {
    if (lhs.slot != rhs.slot) return false;
    if (lhs.index != rhs.index) return false;
    if (lhs.beacon_block_hash != rhs.beacon_block_hash) return false;
    if (*lhs.source != *rhs.source) return false;
    if (*lhs.target != *rhs.target) return false;
    return true;
}

bool operator==(const BeaconBlockHeader& lhs, const BeaconBlockHeader& rhs) {
    if (lhs.slot != rhs.slot) return false;
    if (lhs.proposer_index != rhs.proposer_index) return false;
    if (lhs.parent_root != rhs.parent_root) return false;
    if (lhs.root != rhs.root) return false;
    if (lhs.body_root != rhs.body_root) return false;
    return true;
}

bool operator==(const SignedBeaconBlockHeader& lhs, const SignedBeaconBlockHeader& rhs) {
    if (*lhs.header != *rhs.header) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    return true;
}

bool operator==(const IndexedAttestation& lhs, const IndexedAttestation& rhs) {
    if (lhs.attesting_indices != rhs.attesting_indices) return false;
    if (*lhs.data != *rhs.data) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    return true;
}

}  // namespace silkworm::cl

namespace silkworm::ssz {

template <>
void encode(const cl::Eth1Data& from, Bytes& to) noexcept {
    ssz::encode(from.root, to);
    ssz::encode(from.deposit_count, to);
    ssz::encode(from.block_hash, to);
}

template <>
DecodingResult decode(ByteView& from, cl::Eth1Data& to) noexcept {
    if (from.size() < cl::Eth1Data::kSize) {
        return DecodingResult::kInputTooShort;
    }

    if (DecodingResult err{ssz::decode(from, to.root)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.deposit_count)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.block_hash)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(const cl::Checkpoint& from, Bytes& to) noexcept {
    ssz::encode(from.epoch, to);
    ssz::encode(from.root, to);
}

template <>
DecodingResult decode(ByteView& from, cl::Checkpoint& to) noexcept {
    if (from.size() < cl::Checkpoint::kSize) {
        return DecodingResult::kInputTooShort;
    }

    if (DecodingResult err{ssz::decode(from, to.epoch)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.root)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(const cl::AttestationData& from, Bytes& to) noexcept {
    ssz::encode(from.slot, to);
    ssz::encode(from.index, to);
    ssz::encode(from.beacon_block_hash, to);
    if (from.source) {
        ssz::encode(*from.source, to);
    }
    if (from.target) {
        ssz::encode(*from.target, to);
    }
}

template <>
DecodingResult decode(ByteView& from, cl::AttestationData& to) noexcept {
    if (from.size() < cl::AttestationData::kSize) {
        return DecodingResult::kInputTooShort;
    }

    if (DecodingResult err{ssz::decode(from, to.slot)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.index)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.beacon_block_hash)}; err != DecodingResult::kOk) {
        return err;
    }
    to.source = std::make_unique<cl::Checkpoint>();
    if (DecodingResult err{ssz::decode(from, *to.source)}; err != DecodingResult::kOk) {
        return err;
    }
    to.target = std::make_unique<cl::Checkpoint>();
    if (DecodingResult err{ssz::decode(from, *to.target)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(const cl::BeaconBlockHeader& from, Bytes& to) noexcept {
    ssz::encode(from.slot, to);
    ssz::encode(from.proposer_index, to);
    ssz::encode(from.parent_root, to);
    ssz::encode(from.root, to);
    ssz::encode(from.body_root, to);
}

template <>
DecodingResult decode(ByteView& from, cl::BeaconBlockHeader& to) noexcept {
    if (from.size() < cl::BeaconBlockHeader::kSize) {
        return DecodingResult::kInputTooShort;
    }

    if (DecodingResult err{ssz::decode(from, to.slot)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.proposer_index)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.parent_root)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.root)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.body_root)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(const cl::SignedBeaconBlockHeader& from, Bytes& to) noexcept {
    if (from.header) {
        ssz::encode(*from.header, to);
    }
    ssz::encode(from.signature, to);
}

template <>
DecodingResult decode(ByteView& from, cl::SignedBeaconBlockHeader& to) noexcept {
    if (from.size() < cl::AttestationData::kSize) {
        return DecodingResult::kInputTooShort;
    }

    to.header = std::make_unique<cl::BeaconBlockHeader>();
    if (DecodingResult err{ssz::decode(from, *to.header)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.signature)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(const cl::IndexedAttestation& from, Bytes& to) noexcept {
    ssz::encode_offset(cl::IndexedAttestation::kMinSize, to);
    if (from.data) {
        ssz::encode(*from.data, to);
    }
    ssz::encode(from.signature, to);
    for (const auto attesting_index : from.attesting_indices) {
        ssz::encode(attesting_index, to);
    }
}

template <>
DecodingResult decode(ByteView& from, cl::IndexedAttestation& to) noexcept {
    const auto size = from.size();

    if (from.size() < cl::IndexedAttestation::kMinSize) {
        return DecodingResult::kInputTooShort;
    }
    if (from.size() > cl::IndexedAttestation::kMaxSize) {
        return DecodingResult::kUnexpectedLength;
    }

    uint32_t indices_offset{0};
    if (DecodingResult err{ssz::decode_offset(from, indices_offset)}; err != DecodingResult::kOk) {
        return err;
    }
    if (indices_offset < cl::IndexedAttestation::kMinSize || indices_offset > size) {
        return DecodingResult::kUnexpectedLength;
    }

    to.data = std::make_unique<cl::AttestationData>();
    if (DecodingResult err{ssz::decode(from, *to.data)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{ssz::decode(from, to.signature)}; err != DecodingResult::kOk) {
        return err;
    }
    const auto num_attesting_indices = (size - indices_offset) / CHAR_BIT;
    to.attesting_indices.resize(num_attesting_indices);
    for (std::size_t i{0}; i < num_attesting_indices; ++i) {
        if (DecodingResult err{ssz::decode(from, to.attesting_indices[i])}; err != DecodingResult::kOk) {
            return err;
        }
    }
    return DecodingResult::kOk;
}

}  // namespace silkworm::ssz
