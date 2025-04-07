// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <utility>
#include <vector>

namespace silkworm::test_util {

//! Test fixtures are predefined data sets that you initialize before running your tests
template <typename Input, typename ExpectedResult>
using Fixture = std::pair<Input, ExpectedResult>;

template <typename Input, typename ExpectedResult>
using Fixtures = std::vector<Fixture<Input, ExpectedResult>>;

}  // namespace silkworm::test_util
