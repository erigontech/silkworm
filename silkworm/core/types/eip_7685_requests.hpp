/*
Copyright 2024 The Silkworm Authors

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
    static Bytes extract_deposits_from_logs(const std::vector<Log>& logs);
    void add_request(FlatRequestType type, Bytes data);
    Hash calculate_sha256() const;

  private:
    static constexpr size_t kTypesCount = magic_enum::enum_count<FlatRequestType>();
    std::array<Bytes, kTypesCount> requests_;
};

// struct DepositRequest final : FlatRequest {
//     static constexpr size_t kDepositRequestDataLen = 192;
//     std::array<uint8_t, kDepositRequestDataLen> request_data;
//
//     static Bytes extract_deposits_from_logs(const std::vector<Log>& logs);
//
//     void encode(Bytes& to) const override;
//     DecodingResult decode(ByteView& from, rlp::Leftover mode) override;
// };
//
// struct WithdrawalRequest final : FlatRequest {
//     static constexpr size_t kWithdrawalRequestDataLen = 76;
//     std::array<uint8_t, kWithdrawalRequestDataLen> request_data;
//
//     void encode(Bytes& to) const override;
//     DecodingResult decode(ByteView& from, rlp::Leftover mode) override;
// };
//
// struct ConsolidationRequest final : FlatRequest {
//     static constexpr size_t kConsolidationRequestDataLen = 116;
//     std::array<uint8_t, kConsolidationRequestDataLen> request_data;
//
//     void encode(Bytes& to) const override;
//     DecodingResult decode(ByteView& from, rlp::Leftover mode) override;
// };

namespace rlp {
    // size_t length(const FlatRequest&);
    // void encode(Bytes& to, const FlatRequest&);
    // void encode(Bytes& to, const std::vector<RequestPtr>&);
    // DecodingResult decode(ByteView& from, FlatRequest& to, Leftover mode = Leftover::kProhibit) noexcept;
    // DecodingResult decode(ByteView& from, std::vector<RequestPtr>& to, Leftover mode = Leftover::kAllow) noexcept;
}  // namespace rlp

}  // namespace silkworm