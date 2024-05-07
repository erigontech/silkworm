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

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/grpc/server/server_settings.hpp>

#include "../../api/direct_service.hpp"

namespace silkworm::execution::grpc::server {

class ServerImpl;

class Server final {
  public:
    Server(rpc::ServerSettings settings, std::shared_ptr<api::DirectService> service);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    Task<void> async_run(std::optional<std::size_t> stack_size = {});

  private:
    std::unique_ptr<ServerImpl> p_impl_;
};

}  // namespace silkworm::execution::grpc::server
