// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

struct Encoder {
    virtual ~Encoder() = default;
    virtual Slice encode() = 0;
};

template <class TEncoder>
concept EncoderConcept =
    std::derived_from<TEncoder, Encoder> &&
    requires(TEncoder encoder) { encoder.value; };

struct Decoder {
    virtual ~Decoder() = default;
    virtual void decode(Slice slice) = 0;
};

template <class TDecoder>
concept DecoderConcept =
    std::derived_from<TDecoder, Decoder> &&
    requires(TDecoder decoder) { decoder.value; };

struct Codec : public Encoder, public Decoder {
    ~Codec() override = default;
};

}  // namespace silkworm::datastore::kvdb
