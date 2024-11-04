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

#include "eip_7685_requests.hpp"

#include <type_traits>

#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/types/address.hpp>

namespace silkworm {

Bytes extract_deposit(const Bytes& data) {
    const ByteView input{data};

    Bytes result;

    // The format of deposit data is: (bytes, bytes, bytes, bytes, bytes)
    size_t offset_index = 0;
    for (size_t i = 0; i < 5; ++i) {
        SILKWORM_ASSERT(offset_index < input.size());
        const auto offset = static_cast<uint64_t>(intx::be::unsafe::load<intx::uint256>(input.substr(offset_index).data()));
        SILKWORM_ASSERT(offset < input.size());
        const auto size = static_cast<uint64_t>(intx::be::unsafe::load<intx::uint256>(input.substr(offset).data()));

        if (size > 0) {
            SILKWORM_ASSERT(offset + 32 + size < input.size());
            const auto bytes = input.substr(offset + 32, size);
            std::ranges::copy(bytes, std::back_inserter(result));
        }

        offset_index += 32;
    }

    return result;
}

void FlatRequests::extract_deposits_from_logs(const std::vector<Log>& logs) {
    for (const auto& log : logs) {
        if (log.address == protocol::kDepositContractAddress) {
            auto bytes = extract_deposit(log.data);
            requests_[magic_enum::enum_integer(FlatRequestType::kDepositRequest)] += bytes;
        }
    }
}

void FlatRequests::add_request(FlatRequestType type, Bytes data) {
    requests_[magic_enum::enum_integer(type)] += data;
}

ByteView FlatRequests::preview_data_by_type(FlatRequestType type) const {
    return {requests_[magic_enum::enum_integer(type)]};
}

Hash FlatRequests::calculate_sha256() const {
    Bytes intermediate;

    for (const auto enum_type : magic_enum::enum_values<FlatRequestType>()) {
        const auto request_type = magic_enum::enum_integer(enum_type);
        Bytes to_sha;
        to_sha.push_back(request_type);
        to_sha.append(requests_[request_type]);
        intermediate.append(precompile::sha256_run(ByteView{to_sha}).value());
    }
    const auto final = precompile::sha256_run(intermediate).value();
    return Hash{final};
}

}  // namespace silkworm
