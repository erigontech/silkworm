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

#include <memory>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>
#include <silkworm/lightclient/ssz/ssz_codec.hpp>

namespace silkworm::cl {

static constexpr std::size_t kSignatureSize{96};

//! Eth1Data represents the relevant ETH1 Data for block building.
struct Eth1Data {
    evmc::bytes32 root;
    uint64_t deposit_count{0};
    evmc::bytes32 block_hash;

    static constexpr std::size_t kSize{2 * kHashLength + sizeof(uint64_t)};
};

bool operator==(const Eth1Data& lhs, const Eth1Data& rhs);

//! Checkpoint is used to create the initial store through checkpoint sync.
struct Checkpoint {
    uint64_t epoch{0};
    evmc::bytes32 root;

    static constexpr std::size_t kSize{sizeof(uint64_t) + kHashLength};
};

bool operator==(const Checkpoint& lhs, const Checkpoint& rhs);

//! AttestationData contains information about attestation, including finalized/attested checkpoints.
struct AttestationData {
    uint64_t slot{0};
    uint64_t index{0};
    evmc::bytes32 beacon_block_hash;
    std::unique_ptr<Checkpoint> source;
    std::unique_ptr<Checkpoint> target;

    static constexpr std::size_t kSize{2 * sizeof(uint64_t) + kHashLength + 2 * Checkpoint::kSize};
};

bool operator==(const AttestationData& lhs, const AttestationData& rhs);

//! BeaconBlockHeader contains the block body plus state root hashes and is validated in the lightclient.
struct BeaconBlockHeader {
    uint64_t slot{0};
    uint64_t proposer_index{0};
    evmc::bytes32 parent_root;
    evmc::bytes32 root;
    evmc::bytes32 body_root;

    static constexpr std::size_t kSize{3 * kHashLength + 2 * sizeof(uint64_t)};
};

bool operator==(const BeaconBlockHeader& lhs, const BeaconBlockHeader& rhs);

//! SignedBeaconBlockHeader is a beacon block header + validator signature.
struct SignedBeaconBlockHeader {
    std::unique_ptr<BeaconBlockHeader> header;
    uint8_t signature[kSignatureSize];

    static constexpr std::size_t kSize{BeaconBlockHeader::kSize + kSignatureSize};
};

bool operator==(const SignedBeaconBlockHeader& lhs, const SignedBeaconBlockHeader& rhs);

//! IndexedAttestation are attestantions sets to prove that someone misbehaved.
struct IndexedAttestation {
    std::vector<uint64_t> attesting_indices;
    std::unique_ptr<AttestationData> data;
    uint8_t signature[kSignatureSize];

    static constexpr std::size_t kMaxAttestingIndices{2048};
    static constexpr std::size_t kMinSize{AttestationData::kSize + kSignatureSize + sizeof(uint32_t)};
    static constexpr std::size_t kMaxSize{kMinSize + kMaxAttestingIndices * sizeof(uint64_t)};
};

bool operator==(const IndexedAttestation& lhs, const IndexedAttestation& rhs);

}  // namespace silkworm::cl

namespace silkworm::ssz {

template <>
void encode(const cl::Eth1Data& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView& from, cl::Eth1Data& to) noexcept;

template <>
void encode(const cl::Checkpoint& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView& from, cl::Checkpoint& to) noexcept;

template <>
void encode(const cl::AttestationData& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView& from, cl::AttestationData& to) noexcept;

template <>
void encode(const cl::BeaconBlockHeader& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView& from, cl::BeaconBlockHeader& to) noexcept;

template <>
void encode(const cl::SignedBeaconBlockHeader& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView& from, cl::SignedBeaconBlockHeader& to) noexcept;

template <>
void encode(const cl::IndexedAttestation& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView& from, cl::IndexedAttestation& to) noexcept;

}  // namespace silkworm::ssz
