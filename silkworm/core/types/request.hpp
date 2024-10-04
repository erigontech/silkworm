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

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

static auto constexpr kBLSKeyLen = 48;
static auto constexpr kBLSSignatureLen = 96;

using BLSKey = std::array<uint8_t, kBLSKeyLen>;
using BLSSignature = std::array<uint8_t, kBLSSignatureLen>;

struct Request;
using RequestPtr = std::unique_ptr<Request>;

std::vector<RequestPtr> extract_deposit_requests_from_logs(const std::vector<Log>& logs);

struct Request {
    enum class RequestType : uint8_t {
        DepositRequestType = 0,
        WithdrawalRequestType = 1,
        ConsolidationRequestType = 2
    };

    virtual ~Request() = default;
    virtual void encode(Bytes& to) const = 0;
    virtual size_t length() const = 0;
};

struct DepositRequest final : public Request {
    std::array<uint8_t, kBLSKeyLen> pub_key;
    Hash withdrawal_credentials;
    uint64_t amount = 0;
    BLSSignature signature;
    uint64_t index = 0;

    void encode(Bytes& to) const override;
    size_t length() const override;
};

struct WithdrawalRequest final : public Request {
    evmc::address source_address;
    std::array<uint8_t, kBLSKeyLen> validator_pub_key;
    uint64_t amount{};

    void encode(Bytes& to) const override;
    size_t length() const override;
};

struct ConsolidationRequest final : public Request {
    evmc::address source_address;
    BLSKey source_pub_key;
    BLSKey target_pub_key;

    void encode(Bytes& to) const override;
    size_t length() const override;
};

namespace rlp {
    size_t length(const Request&);
    void encode(Bytes& to, const Request&);
    DecodingResult decode(ByteView& from, Request& to, Leftover mode = Leftover::kProhibit) noexcept;
}  // namespace rlp

}  // namespace silkworm