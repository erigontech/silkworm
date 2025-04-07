// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "context_test_base.hpp"

namespace silkworm::test_util {

ContextTestBase::ContextTestBase()
    : context_{0},
      ioc_{*context_.ioc()},
      grpc_context_{*context_.grpc_context()},
      context_thread_{[&]() { context_.execute_loop(); }} {}

ContextTestBase::~ContextTestBase() {
    context_.stop();
    if (context_thread_.joinable()) {
        context_thread_.join();
    }
}

}  // namespace silkworm::test_util
