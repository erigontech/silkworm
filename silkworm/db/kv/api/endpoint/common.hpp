// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::db::kv::api {

//! Database meta-transaction ID (a transaction over mdbx and snapshots)
using TxId = uint64_t;

using Timestamp = int64_t;
using TimestampRange = std::pair<Timestamp, Timestamp>;

using ListOfBytes = std::vector<Bytes>;
using ListOfTimestamp = std::vector<Timestamp>;

using Domain = uint16_t;
using History = std::string_view;
using InvertedIndex = std::string_view;

}  // namespace silkworm::db::kv::api
