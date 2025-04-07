// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/log.hpp>

namespace silkworm {

// Erigon-compatible CBOR encoding for storage.
// See core/types/log.go
Bytes cbor_encode(const std::vector<Log>& v);

//! LogCborConsumer is the interface to implement for parsing a CBOR-encoded sequence of Logs
struct LogCborConsumer {
    virtual ~LogCborConsumer() = default;

    virtual void on_num_logs(size_t num_logs) = 0;
    virtual void on_address(std::span<const uint8_t, kAddressLength> address_bytes) = 0;
    virtual void on_num_topics(size_t num_topics) = 0;
    virtual void on_topic(HashAsSpan topic_bytes) = 0;
    virtual void on_data(std::span<const uint8_t> data_bytes) = 0;
};

void cbor_decode(ByteView data, LogCborConsumer& consumer);

[[nodiscard]] bool cbor_decode(ByteView data, std::vector<Log>& logs);

}  // namespace silkworm
