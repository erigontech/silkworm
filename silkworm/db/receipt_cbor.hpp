// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

// Erigon-compatible CBOR encoding for storage.
// See core/types/receipt.go and migrations/receipt_cbor.go
Bytes cbor_encode(const std::vector<Receipt>& v);

}  // namespace silkworm
