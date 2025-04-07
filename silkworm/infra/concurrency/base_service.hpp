// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/execution_context.hpp>

namespace silkworm {

template <typename T>
using BaseService = boost::asio::detail::execution_context_service_base<T>;

}  // namespace silkworm
