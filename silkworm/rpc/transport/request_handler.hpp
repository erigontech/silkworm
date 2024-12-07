/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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

    virtual Task<std::optional<Response>> handle(const Request& request) = 0;
};

using RequestHandlerPtr = std::unique_ptr<RequestHandler>;

//! We use \code absl::AnyInvocable waiting for \code std::move_only_function in C++23
using RequestHandlerFactory = absl::AnyInvocable<RequestHandlerPtr(StreamWriter*)>;

}  // namespace silkworm::rpc
