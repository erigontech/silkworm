// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/types/log.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc {

[[nodiscard]] bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Log>& logs);

[[nodiscard]] bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Receipt>& receipts);

}  // namespace silkworm::rpc
