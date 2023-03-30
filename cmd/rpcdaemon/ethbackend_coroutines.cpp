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

#include <exception>
#include <iomanip>
#include <iostream>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/ethbackend/remote_backend.hpp>

using namespace silkworm;
using namespace silkworm::rpc;

inline std::ostream& operator<<(std::ostream& out, const types::H160& address) {
    out << "address=" << address.has_hi();
    if (address.has_hi()) {
        auto& hi_half = address.hi();
        out << std::hex << hi_half.hi() << hi_half.lo();
    } else {
        auto lo_half = address.lo();
        out << std::hex << lo_half;
    }
    out << std::dec;
    return out;
}

boost::asio::awaitable<void> ethbackend_etherbase(ethbackend::BackEnd& backend) {
    try {
        std::cout << "ETHBACKEND Etherbase ->\n";
        const auto address = co_await backend.etherbase();
        std::cout << "ETHBACKEND Etherbase <- address: " << address << "\n";
    } catch (const std::exception& e) {
        std::cout << "ETHBACKEND Etherbase <- error: " << e.what() << "\n";
    }
}

int ethbackend_coroutines(const std::string& target) {
    try {
        // TODO(canepat): handle also secure channel for remote
        ChannelFactory create_channel = [&]() {
            return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
        };
        // TODO(canepat): handle also local (shared-memory) database
        ContextPool context_pool{1, create_channel};
        auto& context = context_pool.next_context();
        auto io_context = context.io_context();
        auto grpc_context = context.grpc_context();

        boost::asio::signal_set signals(*io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "Signal caught, error: " << error.message() << " number: " << signal_number << std::endl
                      << std::flush;
            context_pool.stop();
        });

        const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());

        // Etherbase
        ethbackend::RemoteBackEnd eth_backend{*io_context, channel, *grpc_context};
        boost::asio::co_spawn(*io_context, ethbackend_etherbase(eth_backend), [&](std::exception_ptr) {
            context_pool.stop();
        });

        context_pool.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n"
                  << std::flush;
    } catch (...) {
        std::cerr << "Unexpected exception\n"
                  << std::flush;
    }
    return 0;
}
