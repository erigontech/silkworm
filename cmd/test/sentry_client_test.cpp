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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/rpc/client/call.hpp>
#include <silkworm/infra/rpc/common/util.hpp>
#include <silkworm/infra/rpc/server/server_context_pool.hpp>
#include <silkworm/sentry/rpc/client/sentry_client.hpp>
#include <silkworm/sentry/sentry.hpp>

using namespace silkworm::sentry::rpc::client;
using namespace silkworm;

class DummyServerCompletionQueue : public grpc::ServerCompletionQueue {
};

boost::asio::awaitable<void> run(ISentryClient& client) {
    auto service = client.service();
    try {
        auto eth_version = co_await service->handshake();
        log::Info() << "handshake success!";
        log::Info() << "protocol: eth/" << int(eth_version);

        auto node_info = co_await service->node_info();
        log::Info() << "client_id: " << node_info.client_id;

        auto peer_count = co_await service->peer_count();
        log::Info() << "peer_count: " << peer_count;
    } catch (const rpc::GrpcStatusError& ex) {
        log::Error() << ex.what();
    }
}

int main() {
    log::Settings log_settings;
    log_settings.log_verbosity = log::Level::kDebug;
    log::init(log_settings);
    log::set_thread_name("main");
    // TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    sentry::Settings sentry_settings;

    silkworm::rpc::ServerContextPool context_pool{
        sentry_settings.num_contexts,
        sentry_settings.wait_mode,
        [] { return std::make_unique<DummyServerCompletionQueue>(); },
    };

    SentryClient client{
        sentry_settings.api_address,
        *context_pool.next_context().client_grpc_context(),
    };

    auto run_future = boost::asio::co_spawn(
        context_pool.next_io_context(),
        run(client),
        boost::asio::use_future);

    context_pool.start();

    run_future.get();

    context_pool.stop();
    context_pool.join();

    return 0;
}
