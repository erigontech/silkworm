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

#include <array>
#include <memory>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/decoding_result.hpp>

#include "silkworm/lightclient/ssz/ssz_codec.hpp"
#include "silkworm/lightclient/util/hash32.hpp"
#include "silkworm/lightclient/util/time.hpp"

namespace silkworm::cl {

static constexpr std::size_t kCommiteeBitsSize{64};
static constexpr std::size_t kCredentialsSize{32};
static constexpr std::size_t kPublicKeySize{48};
static constexpr std::size_t kSignatureSize{96};
static constexpr std::size_t kLogsBloomSize{256};
static constexpr std::size_t kSyncCommitteeBranchSize{5};
static constexpr std::size_t kFinalityBranchSize{6};

static constexpr std::size_t kProofHashCount{33};

//! Eth1Data represents the relevant ETH1 information for block building.
struct Eth1Data {
    Hash32 root;
    uint64_t deposit_count{0};
    Hash32 block_hash;

    static constexpr std::size_t kSize{2 * kHashLength + sizeof(uint64_t)};
};

bool operator==(const Eth1Data& lhs, const Eth1Data& rhs);

//! Checkpoint is used to create the initial store through checkpoint sync.
struct Checkpoint {
    uint64_t epoch{0};
    Hash32 root;

    static constexpr std::size_t kSize{sizeof(uint64_t) + kHashLength};
};

bool operator==(const Checkpoint& lhs, const Checkpoint& rhs);

//! AttestationData contains information about attestation, including finalized/attested checkpoints.
struct AttestationData {
    uint64_t slot{0};
    uint64_t index{0};
    Hash32 beacon_block_hash;
    std::shared_ptr<Checkpoint> source;
    std::shared_ptr<Checkpoint> target;

    static constexpr std::size_t kSize{2 * sizeof(uint64_t) + kHashLength + 2 * Checkpoint::kSize};
};

bool operator==(const AttestationData& lhs, const AttestationData& rhs);

//! BeaconBlockHeader contains the block body plus state root hashes and is validated in the LC.
struct BeaconBlockHeader {
    uint64_t slot{0};
    uint64_t proposer_index{0};
    Hash32 parent_root;
    Hash32 root;
    Hash32 body_root;

    static constexpr std::size_t kSize{3 * kHashLength + 2 * sizeof(uint64_t)};

    [[nodiscard]] Hash32 hash_tree_root() {
        return ssz::hash_tree_root(*this);
    }
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
    Hash32 root;  // TODO(canepat) no SSZ, remove?

    static constexpr std::size_t kSize{kPublicKeySize + kCredentialsSize + sizeof(uint64_t) + kSignatureSize};
};

bool operator==(const DepositData& lhs, const DepositData& rhs);

struct Deposit {
    Hash32 proof[kProofHashCount];
    std::shared_ptr<DepositData> data;

    static constexpr std::size_t kSize{kProofHashCount * kHashLength + cl::DepositData::kSize};
};

bool operator==(const Deposit& lhs, const Deposit& rhs);

struct VoluntaryExit {
    uint64_t epoch{0};
    uint64_t validator_index{0};

    static constexpr std::size_t kSize{2 * sizeof(uint64_t)};
};

bool operator==(const VoluntaryExit& lhs, const VoluntaryExit& rhs);

struct SignedVoluntaryExit {
    std::shared_ptr<VoluntaryExit> voluntary_exit;
    uint8_t signature[kSignatureSize]{};

    static constexpr std::size_t kSize{cl::VoluntaryExit::kSize + kSignatureSize};
};

bool operator==(const SignedVoluntaryExit& lhs, const SignedVoluntaryExit& rhs);

//! Determine successful committee: bits shows active participants and signature is the aggregate BLS signature.
struct SyncAggregate {
    uint8_t commitee_bits[kCommiteeBitsSize]{};
    uint8_t commitee_signature[kSignatureSize]{};

    static constexpr std::size_t kSize{kCommiteeBitsSize + kSignatureSize};

    [[nodiscard]] int count_commitee_bits() const;
};

bool operator==(const SyncAggregate& lhs, const SyncAggregate& rhs);

//! Execution payload is sent to EL once validation is done to request block execution.
struct ExecutionPayload {
    Hash32 parent_hash;
    evmc::address fee_recipient;
    Hash32 state_root;
    Hash32 receipts_root;
    uint8_t logs_bloom[kLogsBloomSize];
    Hash32 prev_randao;
    uint64_t block_number{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    uint64_t timestamp{0};
    Bytes extra_data;
    Hash32 base_fee_per_gas;
    Hash32 block_hash;
    std::vector<Bytes> transactions;

    static constexpr std::size_t kMaxExtraDataSize{32};
    static constexpr std::size_t kMaxTransactionCount{1'048'576};
    static constexpr std::size_t kMaxTransactionSize{1'073'741'824};
    static constexpr std::size_t kMinSize{6 * kHashLength + kAddressLength + kLogsBloomSize + 4 * sizeof(uint64_t) + 2 * sizeof(uint32_t)};
    static constexpr std::size_t kMaxSize{kMinSize + kMaxExtraDataSize + kMaxTransactionCount * kMaxTransactionSize};

    [[nodiscard]] std::size_t size() const { return kMinSize + extra_data.size() + size_transactions(); }

  private:
    [[nodiscard]] std::size_t size_transactions() const {
        std::size_t size{0};
        for (const auto& transaction : transactions) {
            size += transaction.size();
        }
        return size;
    }
};

bool operator==(const ExecutionPayload& lhs, const ExecutionPayload& rhs);

using PublicKey = std::array<uint8_t, kPublicKeySize>;

//! Sync commitee public keys and their aggregate public keys.
struct SyncCommittee {
    std::vector<PublicKey> public_keys;
    PublicKey aggregate_public_key;

    [[nodiscard]] Hash32 hash_tree_root() {
        return ssz::hash_tree_root(*this);
    }
};

bool operator==(const SyncCommittee& lhs, const SyncCommittee& rhs);

//! LightClientBootstrap is used to bootstrap the LC from checkpoint sync.
struct LightClientBootstrap {
    std::shared_ptr<BeaconBlockHeader> header;
    std::shared_ptr<SyncCommittee> current_committee;
    std::vector<Hash32> current_committee_branch;

    [[nodiscard]] Hash32 hash_tree_root() const {
        return ssz::hash_tree_root(*this);
    }
};

bool operator==(const LightClientBootstrap& lhs, const LightClientBootstrap& rhs);

//! LightClientUpdate is used to update the sync committee every 27 hours.
struct LightClientUpdate {
    std::shared_ptr<BeaconBlockHeader> attested_header;
    std::shared_ptr<SyncCommittee> next_committee;
    std::vector<Hash32> next_committee_branch;
    std::shared_ptr<BeaconBlockHeader> finalized_header;
    std::vector<Hash32> finality_branch;
    std::shared_ptr<SyncAggregate> sync_aggregate;
    uint64_t signature_slot{0};

    [[nodiscard]] bool is_finality_update() const { return !finality_branch.empty(); }

    [[nodiscard]] bool has_sync_finality() const {
        return finalized_header && slot_to_period(attested_header->slot) == slot_to_period(finalized_header->slot);
    }
};

bool operator==(const LightClientUpdate& lhs, const LightClientUpdate& rhs);

}  // namespace silkworm::cl

namespace silkworm::ssz {

template <>
EncodingResult encode(cl::Eth1Data& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Eth1Data& to) noexcept;

template <>
EncodingResult encode(cl::Checkpoint& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Checkpoint& to) noexcept;

template <>
EncodingResult encode(cl::AttestationData& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::AttestationData& to) noexcept;

template <>
EncodingResult encode(cl::BeaconBlockHeader& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::BeaconBlockHeader& to) noexcept;

template <>
EncodingResult encode(cl::SignedBeaconBlockHeader& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::SignedBeaconBlockHeader& to) noexcept;

template <>
EncodingResult encode(cl::IndexedAttestation& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::IndexedAttestation& to) noexcept;

template <>
EncodingResult encode(cl::ProposerSlashing& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::ProposerSlashing& to) noexcept;

template <>
EncodingResult encode(cl::AttesterSlashing& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::AttesterSlashing& to) noexcept;

template <>
EncodingResult encode(cl::Attestation& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Attestation& to) noexcept;

template <>
EncodingResult encode(cl::DepositData& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::DepositData& to) noexcept;

template <>
EncodingResult encode(cl::Deposit& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::Deposit& to) noexcept;

template <>
EncodingResult encode(cl::VoluntaryExit& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::VoluntaryExit& to) noexcept;

template <>
EncodingResult encode(cl::SignedVoluntaryExit& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::SignedVoluntaryExit& to) noexcept;

template <>
EncodingResult encode(cl::SyncAggregate& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::SyncAggregate& to) noexcept;

template <>
EncodingResult encode(cl::ExecutionPayload& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::ExecutionPayload& to) noexcept;

template <>
EncodingResult encode(cl::SyncCommittee& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::SyncCommittee& to) noexcept;

template <>
EncodingResult encode(cl::LightClientBootstrap& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::LightClientBootstrap& to) noexcept;

template <>
EncodingResult encode(cl::LightClientUpdate& from, Bytes& to) noexcept;

template <>
DecodingResult decode(ByteView from, cl::LightClientUpdate& to) noexcept;

}  // namespace silkworm::ssz
