// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>
#include <silkworm/sentry/grpc/client/sentry_client.hpp>
#include <silkworm/sentry/sentry.hpp>

using namespace silkworm::sentry::grpc::client;
using namespace silkworm;

Task<void> run(sentry::api::SentryClient& client) {
    auto service = co_await client.service();
    try {
        auto eth_version = co_await service->handshake();
        SILK_INFO << "handshake success!";
        SILK_INFO << "protocol: eth/" << int{eth_version};

        auto node_infos = co_await service->node_infos();
        const auto& node_info = node_infos[0];
        SILK_INFO << "client_id: " << node_info.client_id;

        auto peer_count = co_await service->peer_count();
        SILK_INFO << "peer_count: " << peer_count;
    } catch (const rpc::GrpcStatusError& ex) {
        SILK_ERROR << ex.what();
    }
}

int main() {
    log::Settings log_settings;
    log_settings.log_verbosity = log::Level::kDebug;
    log::init(log_settings);
    log::set_thread_name("main");

    sentry::Settings sentry_settings;

    silkworm::rpc::ClientContextPool context_pool{
        sentry_settings.context_pool_settings,
    };

    SentryClient client{
        sentry_settings.api_address,
        context_pool.any_grpc_context(),
    };

    auto run_future = boost::asio::co_spawn(
        context_pool.any_executor(),
        run(client),
        boost::asio::use_future);

    context_pool.start();

    run_future.get();

    context_pool.stop();
    context_pool.join();

    return 0;
}
