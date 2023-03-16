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

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/node/backend/execution/types.hpp>

namespace silkworm::execution {

using boost::asio::awaitable;

class Client {
  public:
    virtual ~Client() = default;

    virtual awaitable<void> start() = 0;

    virtual awaitable<void> insert_headers(const BlockVector& blocks) = 0;

    virtual awaitable<void> insert_bodies(const BlockVector& blocks) = 0;
};

}  // namespace silkworm::execution
