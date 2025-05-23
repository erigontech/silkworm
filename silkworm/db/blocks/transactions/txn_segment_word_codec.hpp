// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <cstdint>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>

namespace silkworm::snapshots {

struct TransactionSegmentWord {
    uint8_t first_hash_byte{};
    ByteView senders_data;
    ByteView tx_rlp;
};

TransactionSegmentWord slice_tx_data(ByteView buffer);

ByteView slice_tx_payload(ByteView tx_rlp);

Hash tx_buffer_hash(ByteView tx_buffer, uint64_t tx_id);

//! Encode transaction as a snapshot word. Format is: tx_hash_1byte + sender_address_20byte + tx_rlp_bytes
void encode_word_from_tx(Bytes& word, const Transaction& tx);

//! Decode transaction from snapshot word. Format is: tx_hash_1byte + sender_address_20byte + tx_rlp_bytes
void decode_word_into_tx(ByteView word, Transaction& tx);

Transaction empty_system_tx();

struct TransactionSegmentWordEncoder : public Encoder {
    Transaction value;
    Bytes word;

    ~TransactionSegmentWordEncoder() override = default;

    ByteView encode_word() override {
        word.clear();
        encode_word_from_tx(word, value);
        return word;
    }
};

static_assert(EncoderConcept<TransactionSegmentWordEncoder>);

struct TransactionSegmentWordDecoder : public Decoder {
    Transaction value;

    ~TransactionSegmentWordDecoder() override = default;

    void decode_word(Word& word) override {
        decode_word_into_tx(word, value);
    }
};

static_assert(DecoderConcept<TransactionSegmentWordDecoder>);

template <BytesOrByteViewConcept TBytes>
struct TransactionSegmentWordPayloadRlpDecoder : public Decoder {
    TBytes value;

    ~TransactionSegmentWordPayloadRlpDecoder() override = default;

    void decode_word(Word& word) override {
        const ByteView word_view = word;
        if (word_view.empty()) {
            value = TBytes{};
            return;
        }

        auto data = slice_tx_data(word_view);
        value = slice_tx_payload(data.tx_rlp);
    }
};

static_assert(DecoderConcept<TransactionSegmentWordPayloadRlpDecoder<Bytes>>);

}  // namespace silkworm::snapshots
