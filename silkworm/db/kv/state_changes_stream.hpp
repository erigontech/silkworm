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

#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>

#include <silkworm/infra/concurrency/task.hpp>
#ifndef BOOST_ASIO_HAS_BOOST_DATE_TIME
#define BOOST_ASIO_HAS_BOOST_DATE_TIME
#endif
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <silkworm/infra/concurrency/cancellation_token.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>

#include "api/client.hpp"
#include "api/state_cache.hpp"
#include "grpc/client/rpc.hpp"

namespace silkworm::db::kv {

//! End-point of the stream of state changes coming from the node Core component
class StateChangesStream {
  public:
    explicit StateChangesStream(rpc::ClientContext& context, api::Client& client);

    //! Open up the stream, starting the register-and-receive loop
    std::future<void> open();

    //! Close down the stream, stopping the register-and-receive loop
    void close();

    //! The register-and-receive asynchronous loop
    Task<void> run();

  private:
    //! Asio execution scheduler running the register-and-receive asynchronous loop
    boost::asio::io_context& ioc_;

    //! The entry point as KV API user
    api::Client& client_;

    //! The local state cache where the received state changes will be applied
    api::StateCache* cache_;

    //! The thread-safe cancellation token for StateChanges KV API
    CancellationToken cancellation_token_;
};

}  // namespace silkworm::db::kv
