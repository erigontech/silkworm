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

#include <bit>

#include <tl/expected.hpp>

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
    if (!lhs.source && rhs.source) return false;
    if (lhs.source && !rhs.source) return false;
    if (lhs.source && rhs.source && *lhs.source != *rhs.source) return false;
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
    if (!lhs.header && rhs.header) return false;
    if (lhs.header && !rhs.header) return false;
    if (lhs.header && rhs.header && *lhs.header != *rhs.header) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    return true;
}

bool operator==(const IndexedAttestation& lhs, const IndexedAttestation& rhs) {
    if (lhs.attesting_indices != rhs.attesting_indices) return false;
    if (!lhs.data && rhs.data) return false;
    if (lhs.data && !rhs.data) return false;
    if (lhs.data && rhs.data && *lhs.data != *rhs.data) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    return true;
}

bool operator==(const ProposerSlashing& lhs, const ProposerSlashing& rhs) {
    if (!lhs.header1 && rhs.header1) return false;
    if (lhs.header1 && !rhs.header1) return false;
    if (lhs.header1 && rhs.header1 && *lhs.header1 != *rhs.header1) return false;
    if (!lhs.header2 && rhs.header2) return false;
    if (lhs.header2 && !rhs.header2) return false;
    if (lhs.header2 && rhs.header2 && *lhs.header2 != *rhs.header2) return false;
    return true;
}

bool operator==(const AttesterSlashing& lhs, const AttesterSlashing& rhs) {
    if (!lhs.attestation1 && rhs.attestation1) return false;
    if (lhs.attestation1 && !rhs.attestation1) return false;
    if (lhs.attestation1 && rhs.attestation1 && *lhs.attestation1 != *rhs.attestation1) return false;
    if (!lhs.attestation2 && rhs.attestation2) return false;
    if (lhs.attestation2 && !rhs.attestation2) return false;
    if (lhs.attestation2 && rhs.attestation2 && *lhs.attestation2 != *rhs.attestation2) return false;
    return true;
}

bool operator==(const Attestation& lhs, const Attestation& rhs) {
    if (lhs.aggregration_bits != rhs.aggregration_bits) return false;
    if (!lhs.data && rhs.data) return false;
    if (lhs.data && !rhs.data) return false;
    if (lhs.data && rhs.data && *lhs.data != *rhs.data) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    return true;
}

bool operator==(const DepositData& lhs, const DepositData& rhs) {
    for (std::size_t i{0}; i < kPublicKeySize; ++i) {
        if (lhs.public_key[i] != rhs.public_key[i]) return false;
    }
    for (std::size_t i{0}; i < kCredentialsSize; ++i) {
        if (lhs.withdrawal_credentials[i] != rhs.withdrawal_credentials[i]) return false;
    }
    if (lhs.amount != rhs.amount) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    if (lhs.root != rhs.root) return false;
    return true;
}

bool operator==(const Deposit& lhs, const Deposit& rhs) {
    for (std::size_t i{0}; i < kProofHashCount; ++i) {
        if (lhs.proof[i] != rhs.proof[i]) return false;
    }
    if (!lhs.data && rhs.data) return false;
    if (lhs.data && !rhs.data) return false;
    if (lhs.data && rhs.data && *lhs.data != *rhs.data) return false;
    return true;
}

bool operator==(const VoluntaryExit& lhs, const VoluntaryExit& rhs) {
    if (lhs.epoch != rhs.epoch) return false;
    if (lhs.validator_index != rhs.validator_index) return false;
    return true;
}

bool operator==(const SignedVoluntaryExit& lhs, const SignedVoluntaryExit& rhs) {
    if (!lhs.voluntary_exit && rhs.voluntary_exit) return false;
    if (lhs.voluntary_exit && !rhs.voluntary_exit) return false;
    if (lhs.voluntary_exit && rhs.voluntary_exit && *lhs.voluntary_exit != *rhs.voluntary_exit) return false;
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.signature[i] != rhs.signature[i]) return false;
    }
    return true;
}

bool operator==(const SyncAggregate& lhs, const SyncAggregate& rhs) {
    for (std::size_t i{0}; i < kCommiteeBitsSize; ++i) {
        if (lhs.commitee_bits[i] != rhs.commitee_bits[i]) return false;
    }
    for (std::size_t i{0}; i < kSignatureSize; ++i) {
        if (lhs.commitee_signature[i] != rhs.commitee_signature[i]) return false;
    }
    return true;
}

int SyncAggregate::count_commitee_bits() const {
    int sum{0};
    for (std::size_t i{0}; i < kCommiteeBitsSize; ++i) {
        sum += std::popcount(commitee_bits[i]);
    }
    return sum;
}

bool operator==(const ExecutionPayload& lhs, const ExecutionPayload& rhs) {
    if (lhs.parent_hash != rhs.parent_hash) return false;
    if (lhs.fee_recipient != rhs.fee_recipient) return false;
    if (lhs.state_root != rhs.state_root) return false;
    if (lhs.receipts_root != rhs.receipts_root) return false;
    for (std::size_t i{0}; i < kLogsBloomSize; ++i) {
        if (lhs.logs_bloom[i] != rhs.logs_bloom[i]) return false;
    }
    if (lhs.prev_randao != rhs.prev_randao) return false;
    if (lhs.block_number != rhs.block_number) return false;
    if (lhs.gas_limit != rhs.gas_limit) return false;
    if (lhs.gas_used != rhs.gas_used) return false;
    if (lhs.timestamp != rhs.timestamp) return false;
    if (lhs.extra_data != rhs.extra_data) return false;
    if (lhs.base_fee_per_gas != rhs.base_fee_per_gas) return false;
    if (lhs.block_hash != rhs.block_hash) return false;
    if (lhs.transactions.size() != rhs.transactions.size()) return false;
    for (std::size_t i{0}; i < lhs.transactions.size(); ++i) {
        if (lhs.transactions[i] != rhs.transactions[i]) return false;
    }
    return true;
}

bool operator==(const SyncCommittee& lhs, const SyncCommittee& rhs) {
    if (lhs.public_keys.size() != rhs.public_keys.size()) return false;
    for (std::size_t i{0}; i < lhs.public_keys.size(); ++i) {
        if (lhs.public_keys[i] != rhs.public_keys[i]) return false;
    }
    for (std::size_t i{0}; i < kPublicKeySize; ++i) {
        if (lhs.aggregate_public_key[i] != rhs.aggregate_public_key[i]) return false;
    }
    return true;
}

bool operator==(const LightClientBootstrap& lhs, const LightClientBootstrap& rhs) {
    if (!lhs.header && rhs.header) return false;
    if (lhs.header && !rhs.header) return false;
    if (lhs.header && rhs.header && *lhs.header != *rhs.header) return false;
    if (!lhs.current_committee && rhs.current_committee) return false;
    if (lhs.current_committee && !rhs.current_committee) return false;
    if (lhs.current_committee && rhs.current_committee && *lhs.current_committee != *rhs.current_committee) return false;
    if (lhs.current_committee_branch != rhs.current_committee_branch) return false;
    return true;
}

bool operator==(const LightClientUpdate& lhs, const LightClientUpdate& rhs) {
    if (!lhs.attested_header && rhs.attested_header) return false;
    if (lhs.attested_header && !rhs.attested_header) return false;
    if (lhs.attested_header && rhs.attested_header && *lhs.attested_header != *rhs.attested_header) return false;
    if (!lhs.next_committee && rhs.next_committee) return false;
    if (lhs.next_committee && !rhs.next_committee) return false;
    if (lhs.next_committee && rhs.next_committee && *lhs.next_committee != *rhs.next_committee) return false;
    if (lhs.next_committee_branch != rhs.next_committee_branch) return false;
    if (!lhs.finalized_header && rhs.finalized_header) return false;
    if (lhs.finalized_header && !rhs.finalized_header) return false;
    if (lhs.finalized_header && rhs.finalized_header && *lhs.finalized_header != *rhs.finalized_header) return false;
    if (lhs.finality_branch != rhs.finality_branch) return false;
    if (!lhs.sync_aggregate && rhs.sync_aggregate) return false;
    if (lhs.sync_aggregate && !rhs.sync_aggregate) return false;
    if (lhs.sync_aggregate && rhs.sync_aggregate && *lhs.sync_aggregate != *rhs.sync_aggregate) return false;
    if (lhs.signature_slot != rhs.signature_slot) return false;
    return true;
}

}  // namespace silkworm::cl

namespace silkworm::ssz {

template <>
EncodingResult encode(cl::Eth1Data& from, Bytes& to) noexcept {
    ssz::encode(from.root, to);
    ssz::encode(from.deposit_count, to);
    ssz::encode(from.block_hash, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::Eth1Data& to) noexcept {
    if (from.size() != cl::Eth1Data::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    ByteView encoded_root{from.substr(pos, kHashLength)};
    if (auto res{ssz::decode(encoded_root, to.root)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += kHashLength;
    ByteView encoded_deposit_count{from.substr(pos, sizeof(uint64_t))};
    if (auto res{ssz::decode(encoded_deposit_count, to.deposit_count)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    ByteView encoded_block_hash{from.substr(pos, kHashLength)};
    if (auto res{ssz::decode(encoded_block_hash, to.block_hash)}; !res) {
        return tl::unexpected(res.error());
    }
    return {};
}

template <>
EncodingResult encode(cl::Checkpoint& from, Bytes& to) noexcept {
    ssz::encode(from.epoch, to);
    ssz::encode(from.root, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::Checkpoint& to) noexcept {
    if (from.size() != cl::Checkpoint::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    ByteView encoded_epoch{from.substr(pos, sizeof(uint64_t))};
    if (auto res{ssz::decode(encoded_epoch, to.epoch)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    ByteView encoded_root{from.substr(pos, kHashLength)};
    if (auto res{ssz::decode(encoded_root, to.root)}; !res) {
        return tl::unexpected(res.error());
    }
    return {};
}

template <>
EncodingResult encode(cl::AttestationData& from, Bytes& to) noexcept {
    ssz::encode(from.slot, to);
    ssz::encode(from.index, to);
    ssz::encode(from.beacon_block_hash, to);
    if (!from.source) {
        from.source = std::make_shared<cl::Checkpoint>();
    }
    (void)ssz::encode(*from.source, to);
    if (!from.target) {
        from.target = std::make_shared<cl::Checkpoint>();
    }
    (void)ssz::encode(*from.target, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::AttestationData& to) noexcept {
    if (from.size() != cl::AttestationData::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.slot)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.index)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.beacon_block_hash)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += kHashLength;
    to.source = std::make_shared<cl::Checkpoint>();
    if (auto res{ssz::decode(from.substr(pos, cl::Checkpoint::kSize), *to.source)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::Checkpoint::kSize;
    to.target = std::make_shared<cl::Checkpoint>();
    if (auto res{ssz::decode(from.substr(pos, cl::Checkpoint::kSize), *to.target)}; !res) {
        return tl::unexpected(res.error());
    }
    return {};
}

template <>
EncodingResult encode(cl::BeaconBlockHeader& from, Bytes& to) noexcept {
    ssz::encode(from.slot, to);
    ssz::encode(from.proposer_index, to);
    ssz::encode(from.parent_root, to);
    ssz::encode(from.root, to);
    ssz::encode(from.body_root, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::BeaconBlockHeader& to) noexcept {
    if (from.size() != cl::BeaconBlockHeader::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.slot)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.proposer_index)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.parent_root)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += kHashLength;
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.root)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += kHashLength;
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.body_root)}; !res) {
        return tl::unexpected(res.error());
    }
    return {};
}

template <>
EncodingResult encode(cl::SignedBeaconBlockHeader& from, Bytes& to) noexcept {
    if (!from.header) {
        from.header = std::make_shared<cl::BeaconBlockHeader>();
    }
    (void)ssz::encode(*from.header, to);
    (void)ssz::encode(from.signature, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::SignedBeaconBlockHeader& to) noexcept {
    if (from.size() != cl::SignedBeaconBlockHeader::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    to.header = std::make_shared<cl::BeaconBlockHeader>();
    if (auto res{ssz::decode(from.substr(pos, cl::BeaconBlockHeader::kSize), *to.header)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::BeaconBlockHeader::kSize;
    if (auto res{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; !res) {
        return tl::unexpected(res.error());
    }
    return {};
}

template <>
EncodingResult encode(cl::IndexedAttestation& from, Bytes& to) noexcept {
    ssz::encode_offset(cl::IndexedAttestation::kMinSize, to);
    if (!from.data) {
        from.data = std::make_shared<cl::AttestationData>();
    }
    (void)ssz::encode(*from.data, to);
    (void)ssz::encode(from.signature, to);

    if (from.attesting_indices.size() > cl::IndexedAttestation::kMaxAttestingIndices) {
        return EncodingResult::kTooManyElements;
    }
    for (const auto attesting_index : from.attesting_indices) {
        ssz::encode(attesting_index, to);
    }
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::IndexedAttestation& to) noexcept {
    const auto size = from.size();
    if (size < cl::IndexedAttestation::kMinSize) {
        return tl::unexpected(DecodingError::kInputTooShort);
    }

    std::size_t pos{0};
    uint32_t offset0{0};
    if (auto res{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset0)}; !res) {
        return tl::unexpected(res.error());
    }
    if (offset0 < cl::IndexedAttestation::kMinSize || offset0 > size) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    pos += sizeof(uint32_t);
    to.data = std::make_shared<cl::AttestationData>();
    if (auto res{ssz::decode(from.substr(pos, cl::AttestationData::kSize), *to.data)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::AttestationData::kSize;
    if (auto res{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; !res) {
        return tl::unexpected(res.error());
    }
    const auto num_attesting_indices = (size - offset0) / CHAR_BIT;
    if (num_attesting_indices > cl::IndexedAttestation::kMaxAttestingIndices) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    pos += cl::kSignatureSize;
    to.attesting_indices.resize(num_attesting_indices);
    for (std::size_t i{0}; i < num_attesting_indices; ++i) {
        if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.attesting_indices[i])}; !res) {
            return tl::unexpected(res.error());
        }
        pos += sizeof(uint64_t);
    }
    return {};
}

template <>
EncodingResult encode(cl::ProposerSlashing& from, Bytes& to) noexcept {
    if (!from.header1) {
        from.header1 = std::make_shared<cl::SignedBeaconBlockHeader>();
    }
    (void)ssz::encode(*from.header1, to);
    if (!from.header2) {
        from.header2 = std::make_shared<cl::SignedBeaconBlockHeader>();
    }
    (void)ssz::encode(*from.header2, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::ProposerSlashing& to) noexcept {
    if (from.size() != cl::ProposerSlashing::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    to.header1 = std::make_shared<cl::SignedBeaconBlockHeader>();
    if (auto res{ssz::decode(from.substr(pos, cl::SignedBeaconBlockHeader::kSize), *to.header1)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::SignedBeaconBlockHeader::kSize;
    to.header2 = std::make_shared<cl::SignedBeaconBlockHeader>();
    if (auto res{ssz::decode(from.substr(pos, cl::SignedBeaconBlockHeader::kSize), *to.header2)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::AttesterSlashing& from, Bytes& to) noexcept {
    std::size_t offset = cl::AttesterSlashing::kMinSize;
    ssz::encode_offset(offset, to);

    if (!from.attestation1) {
        from.attestation1 = std::make_shared<cl::IndexedAttestation>();
    }
    offset += from.attestation1->size();
    ssz::encode_offset(offset, to);

    if (!from.attestation2) {
        from.attestation2 = std::make_shared<cl::IndexedAttestation>();
    }

    (void)ssz::encode(*from.attestation1, to);
    (void)ssz::encode(*from.attestation2, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::AttesterSlashing& to) noexcept {
    const auto size = from.size();
    if (size < cl::AttesterSlashing::kMinSize) {
        return tl::unexpected(DecodingError::kInputTooShort);
    }
    if (size > cl::AttesterSlashing::kMaxSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    uint32_t offset0{0};
    if (auto res{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset0)}; !res) {
        return tl::unexpected(res.error());
    }
    if (offset0 < cl::AttesterSlashing::kMinSize || offset0 > size) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    pos += sizeof(uint32_t);
    uint32_t offset1{0};
    if (auto res{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset1)}; !res) {
        return tl::unexpected(res.error());
    }
    if (offset1 < offset0 || offset1 > size) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    pos += sizeof(uint32_t);
    to.attestation1 = std::make_shared<cl::IndexedAttestation>();
    if (auto res{ssz::decode(from.substr(pos, offset1 - offset0), *to.attestation1)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += offset1 - offset0;
    to.attestation2 = std::make_shared<cl::IndexedAttestation>();
    if (auto res{ssz::decode(from.substr(pos, size - offset1), *to.attestation2)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::Attestation& from, Bytes& to) noexcept {
    ssz::encode_offset(cl::Attestation::kMinSize, to);

    if (!from.data) {
        from.data = std::make_shared<cl::AttestationData>();
    }
    (void)ssz::encode(*from.data, to);
    (void)ssz::encode(from.signature, to);

    if (from.aggregration_bits.size() > cl::Attestation::kMaxAggregationBits) {
        return EncodingResult::kTooManyElements;
    }
    to += from.aggregration_bits;
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::Attestation& to) noexcept {
    const auto size = from.size();
    if (size < cl::Attestation::kMinSize) {
        return tl::unexpected(DecodingError::kInputTooShort);
    }
    if (size > cl::Attestation::kMaxSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    uint32_t offset0{0};
    if (auto res{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset0)}; !res) {
        return tl::unexpected(res.error());
    }
    if (offset0 < cl::Attestation::kMinSize || offset0 > size) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    pos += sizeof(uint32_t);
    to.data = std::make_shared<cl::AttestationData>();
    if (auto res{ssz::decode(from.substr(pos, cl::AttestationData::kSize), *to.data)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::AttestationData::kSize;
    if (auto res{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::kSignatureSize;
    ByteView buffer = from.substr(pos);
    if (auto res{ssz::validate_bitlist(buffer, cl::Attestation::kMaxAggregationBits)}; !res) {
        return tl::unexpected(res.error());
    }

    if (to.aggregration_bits.capacity() == 0) {
        to.aggregration_bits.resize(buffer.size());
    }
    to.aggregration_bits += buffer;

    return {};
}

template <>
EncodingResult encode(cl::DepositData& from, Bytes& to) noexcept {
    (void)ssz::encode(from.public_key, to);
    (void)ssz::encode(from.withdrawal_credentials, to);
    ssz::encode(from.amount, to);
    (void)ssz::encode(from.signature, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::DepositData& to) noexcept {
    if (from.size() != cl::DepositData::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    if (auto res{ssz::decode(from.substr(pos, cl::kPublicKeySize), to.public_key)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::kPublicKeySize;
    if (auto res{ssz::decode(from.substr(pos, cl::kCredentialsSize), to.withdrawal_credentials)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::kCredentialsSize;
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.amount)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    if (auto res{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::Deposit& from, Bytes& to) noexcept {
    for (auto& proof_element : from.proof) {
        ssz::encode(proof_element, to);
    }
    if (!from.data) {
        from.data = std::make_shared<cl::DepositData>();
    }
    (void)ssz::encode(*from.data, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::Deposit& to) noexcept {
    if (from.size() != cl::Deposit::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    for (std::size_t i{0}; i < cl::kProofHashCount; ++i) {
        if (auto res{ssz::decode(from.substr(pos, kHashLength), to.proof[i])}; !res) {
            return tl::unexpected(res.error());
        }
        pos += kHashLength;
    }

    to.data = std::make_shared<cl::DepositData>();
    if (auto res{ssz::decode(from.substr(pos, cl::DepositData::kSize), *to.data)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::VoluntaryExit& from, Bytes& to) noexcept {
    ssz::encode(from.epoch, to);
    ssz::encode(from.validator_index, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::VoluntaryExit& to) noexcept {
    if (from.size() != cl::VoluntaryExit::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.epoch)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += sizeof(uint64_t);
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.validator_index)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::SignedVoluntaryExit& from, Bytes& to) noexcept {
    if (!from.voluntary_exit) {
        from.voluntary_exit = std::make_shared<cl::VoluntaryExit>();
    }
    (void)ssz::encode(*from.voluntary_exit, to);
    (void)ssz::encode(from.signature, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::SignedVoluntaryExit& to) noexcept {
    if (from.size() != cl::SignedVoluntaryExit::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    to.voluntary_exit = std::make_shared<cl::VoluntaryExit>();
    if (auto res{ssz::decode(from.substr(pos, cl::VoluntaryExit::kSize), *to.voluntary_exit)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::VoluntaryExit::kSize;
    if (auto res{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::SyncAggregate& from, Bytes& to) noexcept {
    (void)ssz::encode(from.commitee_bits, to);
    (void)ssz::encode(from.commitee_signature, to);
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::SyncAggregate& to) noexcept {
    if (from.size() != cl::SyncAggregate::kSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    std::size_t pos{0};
    if (auto res{ssz::decode(from.substr(pos, cl::kCommiteeBitsSize), to.commitee_bits)}; !res) {
        return tl::unexpected(res.error());
    }

    pos += cl::kCommiteeBitsSize;
    if (auto res{ssz::decode(from.substr(pos, cl::kSignatureSize), to.commitee_signature)}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::ExecutionPayload& from, Bytes& to) noexcept {
    ssz::encode(from.parent_hash, to);
    ssz::encode(from.fee_recipient, to);
    ssz::encode(from.state_root, to);
    ssz::encode(from.receipts_root, to);
    (void)ssz::encode(from.logs_bloom, to);
    ssz::encode(from.prev_randao, to);
    ssz::encode(from.block_number, to);
    ssz::encode(from.gas_limit, to);
    ssz::encode(from.gas_used, to);
    ssz::encode(from.timestamp, to);

    uint32_t offset = cl::ExecutionPayload::kMinSize;
    ssz::encode_offset(offset, to);

    ssz::encode(from.base_fee_per_gas, to);
    ssz::encode(from.block_hash, to);

    offset += from.extra_data.size();
    ssz::encode_offset(offset, to);

    if (from.extra_data.size() > cl::ExecutionPayload::kMaxExtraDataSize) {
        return EncodingResult::kTooManyElements;
    }
    to += from.extra_data;

    if (from.transactions.size() > cl::ExecutionPayload::kMaxTransactionCount) {
        return EncodingResult::kTooManyElements;
    }
    offset = sizeof(uint32_t) * from.transactions.size();
    for (const auto& transaction : from.transactions) {
        ssz::encode_offset(offset, to);
        offset += transaction.size();
    }
    for (const auto& transaction : from.transactions) {
        if (transaction.size() > cl::ExecutionPayload::kMaxTransactionSize) {
            return EncodingResult::kTooManyElements;
        }
        to += transaction;
    }

    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, cl::ExecutionPayload& to) noexcept {
    const auto size = from.size();
    if (size < cl::ExecutionPayload::kMinSize) {
        return tl::unexpected(DecodingError::kInputTooShort);
    }
    if (size > cl::ExecutionPayload::kMaxSize) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }

    // Field (0) 'parent_hash'
    std::size_t pos{0};
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.parent_hash)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kHashLength;

    // Field (1) 'fee_recipient'
    if (auto res{ssz::decode(from.substr(pos, kAddressLength), to.fee_recipient)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kAddressLength;

    // Field (2) 'state_root'
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.state_root)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kHashLength;

    // Field (3) 'receipts_root'
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.receipts_root)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kHashLength;

    // Field (4) 'logs_bloom'
    if (auto res{ssz::decode(from.substr(pos, cl::kLogsBloomSize), to.logs_bloom)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += cl::kLogsBloomSize;

    // Field (5) 'prev_randao'
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.prev_randao)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kHashLength;

    // Field (6) 'block_number'
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.block_number)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += sizeof(uint64_t);

    // Field (7) 'gas_limit'
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.gas_limit)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += sizeof(uint64_t);

    // Field (8) 'gas_used'
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.gas_used)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += sizeof(uint64_t);

    // Field (9) 'timestamp'
    if (auto res{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.timestamp)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += sizeof(uint64_t);

    // Offset (10) 'extra_data'
    uint32_t offset10{0};
    if (auto res{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset10)}; !res) {
        return tl::unexpected(res.error());
    }
    if (offset10 < cl::ExecutionPayload::kMinSize || offset10 > size) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }
    pos += sizeof(uint32_t);

    // Field (11) 'base_fee_per_gas'
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.base_fee_per_gas)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kHashLength;

    // Field (12) 'block_hash'
    if (auto res{ssz::decode(from.substr(pos, kHashLength), to.block_hash)}; !res) {
        return tl::unexpected(res.error());
    }
    pos += kHashLength;

    // Offset (13) 'transactions'
    uint32_t offset13{0};
    if (auto res{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset13)}; !res) {
        return tl::unexpected(res.error());
    }
    if (offset13 < offset10 || offset13 > size) {
        return tl::unexpected(DecodingError::kUnexpectedLength);
    }
    pos += sizeof(uint32_t);

    // Field (10) 'extra_data'
    const std::size_t extra_data_size = offset13 - offset10;
    to.extra_data.reserve(extra_data_size);
    to.extra_data = from.substr(pos, extra_data_size);
    pos += extra_data_size;

    // Field (13) `transactions`
    std::size_t length{0};
    if (auto res{ssz::decode_dynamic_length(from.substr(pos), 1048576, length)}; !res) {
        return tl::unexpected(res.error());
    }
    to.transactions.resize(length);
    if (auto res{ssz::decode_dynamic(from.substr(pos), length, [&](std::size_t index, ByteView buffer) -> DecodingResult {
            if (buffer.size() > 1073741824) {
                return tl::unexpected(DecodingError::kUnexpectedLength);
            }
            to.transactions[index].resize(buffer.size());
            std::copy(buffer.cbegin(), buffer.cend(), to.transactions[index].begin());
            return {};
        })}; !res) {
        return tl::unexpected(res.error());
    }

    return {};
}

template <>
EncodingResult encode(cl::SyncCommittee& /*from*/, Bytes& /*to*/) noexcept {
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView /*from*/, cl::SyncCommittee& /*to*/) noexcept {
    return {};
}

template <>
EncodingResult encode(cl::LightClientBootstrap& /*from*/, Bytes& /*to*/) noexcept {
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView /*from*/, cl::LightClientBootstrap& /*to*/) noexcept {
    return {};
}

template <>
EncodingResult encode(cl::LightClientUpdate& /*from*/, Bytes& /*to*/) noexcept {
    return EncodingResult::kOk;
}

template <>
DecodingResult decode(ByteView /*from*/, cl::LightClientUpdate& /*to*/) noexcept {
    return {};
}

}  // namespace silkworm::ssz
