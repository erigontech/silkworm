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

static constexpr std::size_t kCredentialsSize{32};
static constexpr std::size_t kPublicKeySize{48};
static constexpr std::size_t kSignatureSize{96};

static constexpr std::size_t kProofHashCount{33};

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
    std::shared_ptr<Checkpoint> source;
    std::shared_ptr<Checkpoint> target;

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
    std::shared_ptr<BeaconBlockHeader> header;
    uint8_t signature[kSignatureSize];

    static constexpr std::size_t kSize{BeaconBlockHeader::kSize + kSignatureSize};
};

bool operator==(const SignedBeaconBlockHeader& lhs, const SignedBeaconBlockHeader& rhs);

//! IndexedAttestation are attestations sets to prove that someone misbehaved.
struct IndexedAttestation {
    std::vector<uint64_t> attesting_indices;
    std::shared_ptr<AttestationData> data;
    uint8_t signature[kSignatureSize];

    static constexpr std::size_t kMaxAttestingIndices{2048};
    static constexpr std::size_t kMinSize{AttestationData::kSize + kSignatureSize + sizeof(uint32_t)};
    static constexpr std::size_t kMaxSize{kMinSize + kMaxAttestingIndices * sizeof(uint64_t)};

    [[nodiscard]] std::size_t size() const { return kMinSize + sizeof(uint64_t) * attesting_indices.size(); }
};

bool operator==(const IndexedAttestation& lhs, const IndexedAttestation& rhs);

//! Slashing requires 2 blocks with the same signer as proof
struct ProposerSlashing {
    std::shared_ptr<SignedBeaconBlockHeader> header1;
    std::shared_ptr<SignedBeaconBlockHeader> header2;

    static constexpr std::size_t kSize{2 * SignedBeaconBlockHeader::kSize};
};

bool operator==(const ProposerSlashing& lhs, const ProposerSlashing& rhs);

//! Slashing data for attester needs to provide valid duplicates as proof
struct AttesterSlashing {
    std::shared_ptr<IndexedAttestation> attestation1;
    std::shared_ptr<IndexedAttestation> attestation2;

    static constexpr std::size_t kMinSize{2 * sizeof(uint32_t)};
    static constexpr std::size_t kMaxSize{2 * IndexedAttestation::kMaxSize};
};

bool operator==(const AttesterSlashing& lhs, const AttesterSlashing& rhs);

//! Full signed attestation
struct Attestation {
    Bytes aggregration_bits;
    std::shared_ptr<AttestationData> data;
    uint8_t signature[kSignatureSize];

    static constexpr std::size_t kMaxAggregationBits{2048};
    static constexpr std::size_t kMinSize{sizeof(uint32_t) + AttestationData::kSize + kSignatureSize};
    static constexpr std::size_t kMaxSize{kMinSize + kMaxAggregationBits};

    [[nodiscard]] std::size_t size() const { return kMinSize + aggregration_bits.size(); }
};

bool operator==(const Attestation& lhs, const Attestation& rhs);

struct DepositData {
    uint8_t public_key[kPublicKeySize]{};
    uint8_t withdrawal_credentials[kCredentialsSize]{};
    uint64_t amount{0};
    uint8_t signature[kSignatureSize]{};
    evmc::bytes32 root;  // TODO(canepat) no SSZ, remove?

    static constexpr std::size_t kSize{kPublicKeySize + kCredentialsSize + sizeof(uint64_t) + kSignatureSize};
};

bool operator==(const DepositData& lhs, const DepositData& rhs);

struct Deposit {
    evmc::bytes32 proof[kProofHashCount];
    std::shared_ptr<DepositData> data;

    static constexpr std::size_t kSize{kProofHashCount * kHashLength + cl::DepositData::kSize};
};

bool operator==(const Deposit& lhs, const Deposit& rhs);

}  // namespace silkworm::cl

namespace silkworm::ssz {

template <>
void encode(cl::Eth1Data& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Eth1Data& to) noexcept;

template <>
void encode(cl::Checkpoint& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Checkpoint& to) noexcept;

template <>
void encode(cl::AttestationData& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::AttestationData& to) noexcept;

template <>
void encode(cl::BeaconBlockHeader& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::BeaconBlockHeader& to) noexcept;

template <>
void encode(cl::SignedBeaconBlockHeader& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::SignedBeaconBlockHeader& to) noexcept;

template <>
void encode(cl::IndexedAttestation& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::IndexedAttestation& to) noexcept;

template <>
void encode(cl::ProposerSlashing& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::ProposerSlashing& to) noexcept;

template <>
void encode(cl::AttesterSlashing& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::AttesterSlashing& to) noexcept;

template <>
void encode(cl::Attestation& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Attestation& to) noexcept;

template <>
void encode(cl::DepositData& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::DepositData& to) noexcept;

template <>
void encode(cl::Deposit& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Deposit& to) noexcept;

}  // namespace silkworm::ssz
