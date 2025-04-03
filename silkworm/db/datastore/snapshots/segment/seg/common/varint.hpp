// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <optional>

#include <absl/functional/function_ref.h>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg::varint {

ByteView encode(Bytes& out, uint64_t value);
std::optional<uint64_t> decode(ByteView& data);
std::optional<ByteView> read(Bytes& out, absl::FunctionRef<char()> get_char);

}  // namespace silkworm::snapshots::seg::varint
