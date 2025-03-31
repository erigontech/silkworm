// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <magic_enum.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

inline static size_t constexpr kBLSKeyLen = 48;
inline static size_t constexpr kBLSSignatureLen = 96;

using BLSKey = std::array<uint8_t, kBLSKeyLen>;
using BLSSignature = std::array<uint8_t, kBLSSignatureLen>;

enum class FlatRequestType : uint8_t {
    kDepositRequest = 0,
    kWithdrawalRequest = 1,
    kConsolidationRequest = 2
};

struct FlatRequests {
    void extract_deposits_from_logs(const std::vector<Log>& logs);
    void add_request(FlatRequestType type, Bytes data);
    Hash calculate_sha256() const;
    ByteView preview_data_by_type(FlatRequestType type) const;

  private:
    static constexpr size_t kTypesCount = magic_enum::enum_count<FlatRequestType>();
    std::array<Bytes, kTypesCount> requests_;
};

}  // namespace silkworm