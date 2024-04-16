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

#include <cstdint>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/transaction.hpp>

#include "snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

struct TransactionSnapshotWord {
    uint8_t first_hash_byte{};
    ByteView senders_data;
    ByteView tx_rlp;
};

TransactionSnapshotWord slice_tx_data(ByteView buffer);

ByteView slice_tx_payload(ByteView tx_rlp);

Hash tx_buffer_hash(ByteView tx_buffer, uint64_t tx_id);

//! Decode transaction from snapshot word. Format is: tx_hash_1byte + sender_address_20byte + tx_rlp_bytes
void decode_word_into_tx(ByteView word, Transaction& tx);

struct TransactionSnapshotWordSerializer : public SnapshotWordSerializer {
    Transaction value;

    ~TransactionSnapshotWordSerializer() override = default;

    void decode_word(ByteView word) override {
        decode_word_into_tx(word, value);
    }
};

struct TransactionSnapshotWordPayloadRlpSerializer : public SnapshotWordSerializer {
    ByteView value;

    ~TransactionSnapshotWordPayloadRlpSerializer() override = default;

    void decode_word(ByteView word) override {
        auto data = slice_tx_data(word);
        value = slice_tx_payload(data.tx_rlp);
    }
};

}  // namespace silkworm::snapshots
