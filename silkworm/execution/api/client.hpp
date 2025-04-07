// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include "service.hpp"

namespace silkworm::execution::api {

struct Client {
    virtual ~Client() = default;

    virtual std::shared_ptr<Service> service() = 0;
};

}  // namespace silkworm::execution::api
