// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "codec.hpp"

namespace silkworm::datastore::kvdb {

struct BigEndianU64Codec : public Codec {
    uint64_t value{0};
    Bytes data;

    BigEndianU64Codec() = default;
    explicit BigEndianU64Codec(uint64_t value1) : value{value1} {}
    ~BigEndianU64Codec() override = default;

    Slice encode() override;
    void decode(Slice slice) override;
};

static_assert(EncoderConcept<BigEndianU64Codec>);
static_assert(DecoderConcept<BigEndianU64Codec>);

}  // namespace silkworm::datastore::kvdb
