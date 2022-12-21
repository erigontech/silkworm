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

}  // namespace silkworm::cl

namespace silkworm::ssz {

template <>
void encode(cl::Eth1Data& from, Bytes& to) noexcept {
    ssz::encode(from.root, to);
    ssz::encode(from.deposit_count, to);
    ssz::encode(from.block_hash, to);
}

template <>
DecodingResult decode(ByteView from, cl::Eth1Data& to) noexcept {
    if (from.size() != cl::Eth1Data::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    ByteView encoded_root{from.substr(pos, kHashLength)};
    if (auto err{ssz::decode(encoded_root, to.root)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += kHashLength;
    ByteView encoded_deposit_count{from.substr(pos, sizeof(uint64_t))};
    if (auto err{ssz::decode(encoded_deposit_count, to.deposit_count)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    ByteView encoded_block_hash{from.substr(pos, kHashLength)};
    if (auto err{ssz::decode(encoded_block_hash, to.block_hash)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(cl::Checkpoint& from, Bytes& to) noexcept {
    ssz::encode(from.epoch, to);
    ssz::encode(from.root, to);
}

template <>
DecodingResult decode(ByteView from, cl::Checkpoint& to) noexcept {
    if (from.size() != cl::Checkpoint::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    ByteView encoded_epoch{from.substr(pos, sizeof(uint64_t))};
    if (auto err{ssz::decode(encoded_epoch, to.epoch)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    ByteView encoded_root{from.substr(pos, kHashLength)};
    if (auto err{ssz::decode(encoded_root, to.root)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(cl::AttestationData& from, Bytes& to) noexcept {
    ssz::encode(from.slot, to);
    ssz::encode(from.index, to);
    ssz::encode(from.beacon_block_hash, to);
    if (!from.source) {
        from.source = std::make_shared<cl::Checkpoint>();
    }
    ssz::encode(*from.source, to);
    if (!from.target) {
        from.target = std::make_shared<cl::Checkpoint>();
    }
    ssz::encode(*from.target, to);
}

template <>
DecodingResult decode(ByteView from, cl::AttestationData& to) noexcept {
    if (from.size() != cl::AttestationData::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    if (auto err{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.slot)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    if (auto err{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.index)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    if (auto err{ssz::decode(from.substr(pos, kHashLength), to.beacon_block_hash)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += kHashLength;
    to.source = std::make_shared<cl::Checkpoint>();
    if (auto err{ssz::decode(from.substr(pos, cl::Checkpoint::kSize), *to.source)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::Checkpoint::kSize;
    to.target = std::make_shared<cl::Checkpoint>();
    if (auto err{ssz::decode(from.substr(pos, cl::Checkpoint::kSize), *to.target)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(cl::BeaconBlockHeader& from, Bytes& to) noexcept {
    ssz::encode(from.slot, to);
    ssz::encode(from.proposer_index, to);
    ssz::encode(from.parent_root, to);
    ssz::encode(from.root, to);
    ssz::encode(from.body_root, to);
}

template <>
DecodingResult decode(ByteView from, cl::BeaconBlockHeader& to) noexcept {
    if (from.size() != cl::BeaconBlockHeader::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    if (auto err{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.slot)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    if (auto err{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.proposer_index)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    if (auto err{ssz::decode(from.substr(pos, kHashLength), to.parent_root)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += kHashLength;
    if (auto err{ssz::decode(from.substr(pos, kHashLength), to.root)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += kHashLength;
    if (auto err{ssz::decode(from.substr(pos, kHashLength), to.body_root)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(cl::SignedBeaconBlockHeader& from, Bytes& to) noexcept {
    if (!from.header) {
        from.header = std::make_shared<cl::BeaconBlockHeader>();
    }
    ssz::encode(*from.header, to);
    ssz::encode(from.signature, to);
}

template <>
DecodingResult decode(ByteView from, cl::SignedBeaconBlockHeader& to) noexcept {
    if (from.size() != cl::SignedBeaconBlockHeader::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    to.header = std::make_shared<cl::BeaconBlockHeader>();
    if (auto err{ssz::decode(from.substr(pos, cl::BeaconBlockHeader::kSize), *to.header)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::BeaconBlockHeader::kSize;
    if (auto err{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; err != DecodingResult::kOk) {
        return err;
    }
    return DecodingResult::kOk;
}

template <>
void encode(cl::IndexedAttestation& from, Bytes& to) noexcept {
    ssz::encode_offset(cl::IndexedAttestation::kMinSize, to);
    if (!from.data) {
        from.data = std::make_shared<cl::AttestationData>();
    }
    ssz::encode(*from.data, to);
    ssz::encode(from.signature, to);

    // TODO(canepat) support encoding errors
    /*if (from.attesting_indices.size() > cl::IndexedAttestation::kMaxAttestingIndices) {
        return EncodingResult::kTooManyElements;
    }*/
    for (const auto attesting_index : from.attesting_indices) {
        ssz::encode(attesting_index, to);
    }
}

template <>
DecodingResult decode(ByteView from, cl::IndexedAttestation& to) noexcept {
    const auto size = from.size();
    if (size < cl::IndexedAttestation::kMinSize) {
        return DecodingResult::kInputTooShort;
    }

    std::size_t pos{0};
    uint32_t offset0{0};
    if (auto err{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset0)}; err != DecodingResult::kOk) {
        return err;
    }
    if (offset0 < cl::IndexedAttestation::kMinSize || offset0 > size) {
        return DecodingResult::kUnexpectedLength;
    }

    pos += sizeof(uint32_t);
    to.data = std::make_shared<cl::AttestationData>();
    if (auto err{ssz::decode(from.substr(pos, cl::AttestationData::kSize), *to.data)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::AttestationData::kSize;
    if (auto err{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; err != DecodingResult::kOk) {
        return err;
    }
    const auto num_attesting_indices = (size - offset0) / CHAR_BIT;
    if (num_attesting_indices > cl::IndexedAttestation::kMaxAttestingIndices) {
        return DecodingResult::kUnexpectedLength;
    }

    pos += cl::kSignatureSize;
    to.attesting_indices.resize(num_attesting_indices);
    for (std::size_t i{0}; i < num_attesting_indices; ++i) {
        if (auto err{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.attesting_indices[i])}; err != DecodingResult::kOk) {
            return err;
        }
        pos += sizeof(uint64_t);
    }
    return DecodingResult::kOk;
}

template <>
void encode(cl::ProposerSlashing& from, Bytes& to) noexcept {
    if (!from.header1) {
        from.header1 = std::make_shared<cl::SignedBeaconBlockHeader>();
    }
    ssz::encode(*from.header1, to);
    if (!from.header2) {
        from.header2 = std::make_shared<cl::SignedBeaconBlockHeader>();
    }
    ssz::encode(*from.header2, to);
}

template <>
DecodingResult decode(ByteView from, cl::ProposerSlashing& to) noexcept {
    if (from.size() != cl::ProposerSlashing::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    to.header1 = std::make_shared<cl::SignedBeaconBlockHeader>();
    if (auto err{ssz::decode(from.substr(pos, cl::SignedBeaconBlockHeader::kSize), *to.header1)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::SignedBeaconBlockHeader::kSize;
    to.header2 = std::make_shared<cl::SignedBeaconBlockHeader>();
    if (auto err{ssz::decode(from.substr(pos, cl::SignedBeaconBlockHeader::kSize), *to.header2)}; err != DecodingResult::kOk) {
        return err;
    }

    return DecodingResult::kOk;
}

template <>
void encode(cl::AttesterSlashing& from, Bytes& to) noexcept {
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

    ssz::encode(*from.attestation1, to);
    ssz::encode(*from.attestation2, to);
}

template <>
DecodingResult decode(ByteView from, cl::AttesterSlashing& to) noexcept {
    const auto size = from.size();
    if (size < cl::AttesterSlashing::kMinSize) {
        return DecodingResult::kInputTooShort;
    }
    if (size > cl::AttesterSlashing::kMaxSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    uint32_t offset0{0};
    if (auto err{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset0)}; err != DecodingResult::kOk) {
        return err;
    }
    if (offset0 < cl::AttesterSlashing::kMinSize || offset0 > size) {
        return DecodingResult::kUnexpectedLength;
    }

    pos += sizeof(uint32_t);
    uint32_t offset1{0};
    if (auto err{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset1)}; err != DecodingResult::kOk) {
        return err;
    }
    if (offset1 < offset0 || offset1 > size) {
        return DecodingResult::kUnexpectedLength;
    }

    pos += sizeof(uint32_t);
    to.attestation1 = std::make_shared<cl::IndexedAttestation>();
    if (auto err{ssz::decode(from.substr(pos, offset1 - offset0), *to.attestation1)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += offset1 - offset0;
    to.attestation2 = std::make_shared<cl::IndexedAttestation>();
    if (auto err{ssz::decode(from.substr(pos, size - offset1), *to.attestation2)}; err != DecodingResult::kOk) {
        return err;
    }

    return DecodingResult::kOk;
}

template <>
void encode(cl::Attestation& from, Bytes& to) noexcept {
    ssz::encode_offset(cl::Attestation::kMinSize, to);

    if (!from.data) {
        from.data = std::make_shared<cl::AttestationData>();
    }
    ssz::encode(*from.data, to);
    ssz::encode(from.signature, to);

    // TODO(canepat) support encoding errors
    /*if (from.aggregration_bits.size() > cl::Attestation::kMaxAggregationBits) {
        return EncodingResult::kTooManyElements;
    }*/
    to += from.aggregration_bits;
}

template <>
DecodingResult decode(ByteView from, cl::Attestation& to) noexcept {
    const auto size = from.size();
    if (size < cl::Attestation::kMinSize) {
        return DecodingResult::kInputTooShort;
    }
    if (size > cl::Attestation::kMaxSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    uint32_t offset0{0};
    if (auto err{ssz::decode_offset(from.substr(pos, sizeof(uint32_t)), offset0)}; err != DecodingResult::kOk) {
        return err;
    }
    if (offset0 < cl::Attestation::kMinSize || offset0 > size) {
        return DecodingResult::kUnexpectedLength;
    }

    pos += sizeof(uint32_t);
    to.data = std::make_shared<cl::AttestationData>();
    if (auto err{ssz::decode(from.substr(pos, cl::AttestationData::kSize), *to.data)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::AttestationData::kSize;
    if (auto err{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::kSignatureSize;
    ByteView buffer = from.substr(pos);
    if (auto err{ssz::validate_bitlist(buffer, cl::Attestation::kMaxAggregationBits)}; err != DecodingResult::kOk) {
        return err;
    }

    if (to.aggregration_bits.capacity() == 0) {
        to.aggregration_bits.resize(buffer.size());
    }
    to.aggregration_bits += buffer;

    return DecodingResult::kOk;
}

template <>
void encode(cl::DepositData& from, Bytes& to) noexcept {
    ssz::encode(from.public_key, to);
    ssz::encode(from.withdrawal_credentials, to);
    ssz::encode(from.amount, to);
    ssz::encode(from.signature, to);
}

template <>
DecodingResult decode(ByteView from, cl::DepositData& to) noexcept {
    if (from.size() != cl::DepositData::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    if (auto err{ssz::decode(from.substr(pos, cl::kPublicKeySize), to.public_key)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::kPublicKeySize;
    if (auto err{ssz::decode(from.substr(pos, cl::kCredentialsSize), to.withdrawal_credentials)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += cl::kCredentialsSize;
    if (auto err{ssz::decode(from.substr(pos, sizeof(uint64_t)), to.amount)}; err != DecodingResult::kOk) {
        return err;
    }

    pos += sizeof(uint64_t);
    if (auto err{ssz::decode(from.substr(pos, cl::kSignatureSize), to.signature)}; err != DecodingResult::kOk) {
        return err;
    }

    return DecodingResult::kOk;
}

template <>
void encode(cl::Deposit& from, Bytes& to) noexcept {
    for (auto& proof_element : from.proof) {
        ssz::encode(proof_element, to);
    }
    if (!from.data) {
        from.data = std::make_shared<cl::DepositData>();
    }
    ssz::encode(*from.data, to);
}

template <>
DecodingResult decode(ByteView from, cl::Deposit& to) noexcept {
    if (from.size() != cl::Deposit::kSize) {
        return DecodingResult::kUnexpectedLength;
    }

    std::size_t pos{0};
    for (std::size_t i{0}; i < cl::kProofHashCount; ++i) {
        if (auto err{ssz::decode(from.substr(pos, kHashLength), to.proof[i])}; err != DecodingResult::kOk) {
            return err;
        }
        pos += kHashLength;
    }

    to.data = std::make_shared<cl::DepositData>();
    if (auto err{ssz::decode(from.substr(pos, cl::DepositData::kSize), *to.data)}; err != DecodingResult::kOk) {
        return err;
    }

    return DecodingResult::kOk;
}

}  // namespace silkworm::ssz
