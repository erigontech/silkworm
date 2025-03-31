// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots {

class SnapshotPath;

struct Encoder {
    virtual ~Encoder() = default;
    virtual ByteView encode_word() = 0;
};

template <class TEncoder>
concept EncoderConcept =
    std::derived_from<TEncoder, Encoder> &&
    requires(TEncoder encoder) { encoder.value; };

struct Decoder {
    virtual ~Decoder() = default;
    using Word = BytesOrByteView;
    virtual void decode_word(Word& word) = 0;  // this allows word to be moved after decoding
    virtual void check_sanity_with_metadata(const SnapshotPath& /*path*/) {}
};

template <class TDecoder>
concept DecoderConcept =
    std::derived_from<TDecoder, Decoder> &&
    requires(TDecoder decoder) { decoder.value; };

struct Codec : public Encoder, public Decoder {
    ~Codec() override = default;
};

}  // namespace silkworm::snapshots
