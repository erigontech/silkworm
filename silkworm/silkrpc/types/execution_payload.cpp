/*
   Copyright 2020 The Silkrpc Authors

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

#include "execution_payload.hpp"
#include <silkworm/silkrpc/common/util.hpp>

namespace silkrpc {
std::ostream& operator<<(std::ostream& out, const ExecutionPayload& payload) {
    auto bloom_bytes{silkworm::ByteView(&payload.logs_bloom[0], 256)};
    out << "number: " << payload.number
    << " block_hash: " << payload.block_hash
    << " parent_hash: " << payload.parent_hash
    << " timestamp: " << payload.timestamp
    << " gas_limit: " << payload.gas_limit
    << " gas_used: " << payload.gas_used
    << " suggested_fee_recipient: " << payload.suggested_fee_recipient
    << " state_root: " << payload.state_root
    << " receipts_root: " << payload.receipts_root
    << " prev_randao: " << payload.prev_randao
    << " logs_bloom: " << silkworm::to_hex(bloom_bytes)
    << " extra_data: " << silkworm::to_hex(payload.extra_data)
    << "#transactions: " << payload.transactions.size();

    return out;
}

std::ostream& operator<<(std::ostream& out, const PayloadStatus& payload_status) {
    out << "status: " << payload_status.status;

    if (payload_status.latest_valid_hash) {
        out << " latest_valid_hash: " << *payload_status.latest_valid_hash;
    }
    if (payload_status.validation_error) {
        out << " validation_error: " << *payload_status.validation_error;
    }

    return out;
}
} // namespace silkrpc
