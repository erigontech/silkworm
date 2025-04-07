// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <tl/expected.hpp>

namespace silkworm {

// Error codes for RLP and other decoding
enum class [[nodiscard]] DecodingError {
    kOverflow,
    kLeadingZero,
    kInputTooShort,
    kInputTooLong,
    kNonCanonicalSize,
    kUnexpectedLength,
    kUnexpectedString,
    kUnexpectedList,
    kUnexpectedListElements,
    kInvalidVInSignature,         // v != 27 && v != 28 && v < 35, see EIP-155
    kUnsupportedTransactionType,  // EIP-2718
    kInvalidFieldset,
    kUnexpectedEip2718Serialization,
    kInvalidHashesLength,  // trie::Node decoding
    kInvalidMasksSubsets,  // trie::Node decoding
};

// TODO(C++23) Switch to std::expected
using DecodingResult = tl::expected<void, DecodingError>;

}  // namespace silkworm
