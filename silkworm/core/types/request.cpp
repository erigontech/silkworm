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

#include "request.hpp"

#include <type_traits>

#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/address.hpp>

namespace silkworm {

std::vector<RequestPtr> extract_deposit_requests_from_logs(const std::vector<Log>& logs) {
    for (const auto& log : logs) {
        if (log.address != protocol::kDepositContractAddress) {
            continue;
        }
    }
    std::vector<RequestPtr> requests;

    return requests;
}

static rlp::Header compute_header(const DepositRequest& request) {
    rlp::Header header{.list = true};
    header.payload_length += rlp::length(request.pub_key);
    header.payload_length += rlp::length(request.withdrawal_credentials);
    header.payload_length += rlp::length(request.amount);
    header.payload_length += rlp::length(request.signature);
    header.payload_length += rlp::length(request.index);
    return header;
}

static rlp::Header compute_header(const WithdrawalRequest& request) {
    rlp::Header header{.list = true};
    header.payload_length += rlp::length(request.source_address);
    header.payload_length += rlp::length(request.validator_pub_key);
    header.payload_length += rlp::length(request.amount);
    return header;
}

void DepositRequest::encode(Bytes& to) const {
    const auto header = compute_header(*this);
    using underlying = std::underlying_type_t<Request::RequestType>;
    rlp::encode(to, static_cast<underlying>(Request::RequestType::DepositRequestType));
    rlp::encode_header(to, header);
    rlp::encode(to, pub_key);
    rlp::encode(to, withdrawal_credentials);
    rlp::encode(to, amount);
    rlp::encode(to, signature);
    rlp::encode(to, index);
}

size_t DepositRequest::length() const {
    rlp::Header header{.list = true};
    header.payload_length += rlp::length(pub_key);
    header.payload_length += rlp::length(withdrawal_credentials);
    header.payload_length += rlp::length(amount);
    header.payload_length += rlp::length(signature);
    header.payload_length += rlp::length(index);
    return rlp::length_of_length(header.payload_length) + header.payload_length;
}

void WithdrawalRequest::encode(Bytes& to) const {
    const auto header = compute_header(*this);
    using underlying = std::underlying_type_t<Request::RequestType>;
    rlp::encode(to, static_cast<underlying>(Request::RequestType::WithdrawalRequestType));
    rlp::encode_header(to, header);
    rlp::encode(to, source_address);
    rlp::encode(to, validator_pub_key);
    rlp::encode(to, amount);
}

size_t WithdrawalRequest::length() const {
    rlp::Header header{.list = true};
    header.payload_length += rlp::length(source_address);
    header.payload_length += rlp::length(validator_pub_key);
    header.payload_length += rlp::length(amount);
    return rlp::length_of_length(header.payload_length) + header.payload_length;
}

void ConsolidationRequest::encode(Bytes& /*to*/) const {
}

size_t ConsolidationRequest::length() const {
    return 0;
}

namespace rlp {

    size_t length(const Request& request) {
        return request.length();
    }

    void encode(Bytes& to, const Request& request) {
        request.encode(to);
    }

    DecodingResult decode(ByteView& /*from*/, Request& /*to*/, Leftover /*mode*/) noexcept {
        return {};
    }

}  // namespace rlp

}  // namespace silkworm
