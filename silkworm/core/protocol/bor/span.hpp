// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/execution/evm.hpp>

namespace silkworm::protocol::bor {

struct Span {
    uint64_t id{0};
    BlockNum start_block{0};
    BlockNum end_block{0};
};

// See GetCurrentSpan in polygon/bor/spanner.go
std::optional<Span> get_current_span(EVM& evm, const evmc_address& validator_contract);

}  // namespace silkworm::protocol::bor
