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

    virtual void on_num_logs(std::size_t num_logs) = 0;
    virtual void on_address(std::span<const uint8_t, kAddressLength> address_bytes) = 0;
    virtual void on_num_topics(std::size_t num_topics) = 0;
    virtual void on_topic(HashAsSpan topic_bytes) = 0;
    virtual void on_data(std::span<const uint8_t> data_bytes) = 0;
};

void cbor_decode(ByteView data, LogCborConsumer& consumer);

[[nodiscard]] bool cbor_decode(ByteView data, std::vector<Log>& logs);

}  // namespace silkworm
