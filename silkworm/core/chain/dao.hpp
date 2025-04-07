// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/state/intra_block_state.hpp>

namespace silkworm {

// EIP-779: Hardfork Meta: DAO Fork
void transfer_dao_balances(IntraBlockState& state);

}  // namespace silkworm
