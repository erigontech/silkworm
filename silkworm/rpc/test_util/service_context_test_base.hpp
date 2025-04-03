// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::rpc::test_util {

using silkworm::test_util::ContextTestBase;

class ServiceContextTestBase : public ContextTestBase {
  public:
    ServiceContextTestBase();
    ~ServiceContextTestBase() = default;
};

}  // namespace silkworm::rpc::test_util
