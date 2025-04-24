// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/functional/any_invocable.h>

#include "stream_writer.hpp"

namespace silkworm::rpc {

using Request = std::string;
using Response = std::string;

class RequestHandler {
  public:
    RequestHandler() = default;
    virtual ~RequestHandler() = default;

    RequestHandler(const RequestHandler&) = delete;
    RequestHandler& operator=(const RequestHandler&) = delete;

    virtual Task<std::optional<Response>> handle(const Request& request, uint64_t request_id) = 0;
};

using RequestHandlerPtr = std::unique_ptr<RequestHandler>;

//! We use \code absl::AnyInvocable waiting for \code std::move_only_function in C++23
using RequestHandlerFactory = absl::AnyInvocable<RequestHandlerPtr(StreamWriter*)>;

}  // namespace silkworm::rpc
