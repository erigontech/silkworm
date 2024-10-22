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

std::vector<RequestPtr> DepositRequest::extract_deposits_from_logs(const std::vector<Log>& logs) {
    for (const auto& log : logs) {
        if (log.address != protocol::kDepositContractAddress) {
            continue;
        }
    }
    std::vector<RequestPtr> requests;

    return requests;
}

void DepositRequest::encode(Bytes& to) const {
    using underlying = std::underlying_type_t<Request::RequestType>;
    to.push_back(static_cast<underlying>(Request::RequestType::kDepositRequestType));
    to.insert(std::end(to), std::begin(request_data), std::end(request_data));
}

DecodingResult DepositRequest::decode(ByteView& from, rlp::Leftover mode) {
    from.remove_prefix(1);
    std::ranges::copy_n(std::begin(from), kDepositRequestDataLen, std::begin(request_data));
    from.remove_prefix(kDepositRequestDataLen);
    if (mode != rlp::Leftover::kAllow && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

void WithdrawalRequest::encode(Bytes& to) const {
    using underlying = std::underlying_type_t<Request::RequestType>;
    to.push_back(static_cast<underlying>(Request::RequestType::kDepositRequestType));
    to.insert(std::end(to), std::begin(request_data), std::end(request_data));
}

DecodingResult WithdrawalRequest::decode(ByteView& from, rlp::Leftover mode) {
    from.remove_prefix(1);
    std::ranges::copy_n(std::begin(from), kWithdrawalRequestDataLen, std::begin(request_data));
    from.remove_prefix(kWithdrawalRequestDataLen);
    if (mode != rlp::Leftover::kAllow && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

void ConsolidationRequest::encode(Bytes& to) const {
    using underlying = std::underlying_type_t<Request::RequestType>;
    to.push_back(static_cast<underlying>(Request::RequestType::kConsolidationRequestType));
    to.insert(std::end(to), std::begin(request_data), std::end(request_data));
}

DecodingResult ConsolidationRequest::decode(ByteView& from, rlp::Leftover mode) {
    from.remove_prefix(1);
    std::ranges::copy_n(std::begin(from), kConsolidationRequestDataLen, std::begin(request_data));
    from.remove_prefix(kConsolidationRequestDataLen);
    if (mode != rlp::Leftover::kAllow && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

namespace rlp {
    void encode(Bytes& to, const Request& request) {
        request.encode(to);
    }

    void encode(Bytes& to, const std::vector<RequestPtr>& requests) {
        std::vector<RlpBytes> encoded_elements;
        for (const auto& request : requests) {
            Bytes encoded_request;
            encode(encoded_request, *request);
            encoded_elements.push_back(RlpBytes{std::move(encoded_request)});
        }
        encode(to, std::span<const RlpBytes>{encoded_elements.data(), encoded_elements.size()});
    }

    DecodingResult decode(ByteView& input, Request& to, Leftover mode) noexcept {
        return to.decode(input, mode);
    }

}  // namespace rlp

}  // namespace silkworm
