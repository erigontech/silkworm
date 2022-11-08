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

    static constexpr std::size_t kSize{72};
};

bool operator==(const Eth1Data& lhs, const Eth1Data& rhs);

//! Checkpoint is used to create the initial store through checkpoint sync.
struct Checkpoint {
    uint64_t epoch{0};
    evmc::bytes32 root;

    static constexpr std::size_t kSize{40};
};

bool operator==(const Checkpoint& lhs, const Checkpoint& rhs);

//! AttestationData contains information about attestation, including finalized/attested checkpoints.
struct AttestationData {
    uint64_t slot{0};
    uint64_t index{0};
    evmc::bytes32 beacon_block_hash;
    std::unique_ptr<Checkpoint> source;
    std::unique_ptr<Checkpoint> target;

    static constexpr std::size_t kSize{128};
};

bool operator==(const AttestationData& lhs, const AttestationData& rhs);

//! BeaconBlockHeader contains the block body plus state root hashes and is validated in the lightclient.
struct BeaconBlockHeader {
    uint64_t slot{0};
    uint64_t proposer_index{0};
    evmc::bytes32 parent_root;
    evmc::bytes32 root;
    evmc::bytes32 body_root;

    static constexpr std::size_t kSize{112};
};

bool operator==(const BeaconBlockHeader& lhs, const BeaconBlockHeader& rhs);

//! SignedBeaconBlockHeader is a beacon block header + validator signature.
struct SignedBeaconBlockHeader {
    std::unique_ptr<BeaconBlockHeader> header;
    uint8_t signature[kSignatureSize];

    static constexpr std::size_t kSize{208};
};

bool operator==(const SignedBeaconBlockHeader& lhs, const SignedBeaconBlockHeader& rhs);

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

}  // namespace silkworm::ssz
