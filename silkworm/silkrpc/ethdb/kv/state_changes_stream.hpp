/*
    Copyright 2020-2022 The Silkrpc Authors

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
#include <functional>
#include <future>
#include <memory>

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#ifndef BOOST_ASIO_HAS_BOOST_DATE_TIME
#define BOOST_ASIO_HAS_BOOST_DATE_TIME
#endif
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/ethdb/kv/rpc.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

//! Unfortunately gRPC does not define operator<< for generated data types
namespace remote {

inline std::ostream& operator<<(std::ostream& out, const remote::StateChangeBatch& batch) {
    out << "changebatch_size=" << batch.changebatch_size() << " stateversionid=" << batch.stateversionid()
        << " pendingblockbasefee=" << batch.pendingblockbasefee() << " blockgaslimit=" << batch.blockgaslimit();
    return out;
}

} // namespace remote

namespace silkrpc::ethdb::kv {

//! The default registration interval
constexpr boost::posix_time::milliseconds kDefaultRegistrationInterval{10'000};

//! End-point of the stream of state changes coming from the node Core component
class StateChangesStream {
public:
    //! Return the retry interval between successive registration attempts
    static boost::posix_time::milliseconds registration_interval() { return registration_interval_; }

    //! Set the retry interval between successive registration attempts
    static void set_registration_interval(boost::posix_time::milliseconds registration_interval);

    explicit StateChangesStream(Context& context, remote::KV::StubInterface* stub);

    //! Open up the stream, starting the register-and-receive loop
    std::future<void> open();

    //! Close down the stream, stopping the register-and-receive loop
    void close();

    // The register-and-receive asynchronous loop
    boost::asio::awaitable<void> run();

private:
    //! The retry interval between successive registration attempts
    static boost::posix_time::milliseconds registration_interval_;

    //! Asio execution scheduler running the register-and-receive asynchronous loop
    boost::asio::io_context& scheduler_;

    //! gRPC execution scheduler running the register-and-receive asynchronous loop
    agrpc::GrpcContext& grpc_context_;

    //! The gRPC stub for remote KV interface of the Core component
    remote::KV::StubInterface* stub_;

    //! The local state cache where the received state changes will be applied
    StateCache* cache_;

    //! The signal used to cancel the register-and-receive stream loop
    boost::asio::cancellation_signal cancellation_signal_;

    //! The state changes request options
    remote::StateChangeRequest request_;

    //! The timer to schedule retries for stream opening
    boost::asio::deadline_timer retry_timer_;
};

} // namespace silkrpc::ethdb::kv

