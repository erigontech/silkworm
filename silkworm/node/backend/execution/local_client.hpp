/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/node/backend/execution/execution_client.hpp>
#include <silkworm/node/backend/execution/execution_server.hpp>

namespace silkworm::execution {

class LocalClient : public Client {
  public:
    explicit LocalClient(Server* local_server);

    awaitable<void> start() override;

    awaitable<void> insert_headers(const BlockVector& blocks) override;

    awaitable<void> insert_bodies(const BlockVector& blocks) override;

  private:
    Server* local_server_;
};

}  // namespace silkworm::execution
