// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sentry_client_factory.hpp"

#include "grpc/client/sentry_client.hpp"
#include "multi_sentry_client.hpp"

namespace silkworm::sentry {

SentryClientFactory::SentryPtrPair SentryClientFactory::make_sentry(
    Settings sentry_settings,
    const std::vector<std::string>& remote_sentry_addresses,
    concurrency::ExecutorPool& executor_pool,
    rpc::GrpcContextPool& grpc_context_pool,
    SessionSentryClient::StatusDataProvider eth_status_data_provider) {
    SentryServerPtr sentry_server;
    SentryClientPtr sentry_client;

    if (remote_sentry_addresses.empty()) {
        // Disable gRPC in the embedded sentry
        sentry_settings.api_address = "";

        // Create embedded server
        sentry_server = std::make_shared<Sentry>(std::move(sentry_settings), executor_pool);

        // Wrap direct client (i.e. the server) in a session client
        sentry_client = std::make_shared<SessionSentryClient>(
            sentry_server,
            std::move(eth_status_data_provider));
    } else {
        std::vector<SentryClientPtr> clients;

        for (const auto& address_uri : remote_sentry_addresses) {
            // Create remote client
            auto remote_sentry_client = std::make_shared<grpc::client::SentryClient>(
                address_uri,
                grpc_context_pool.any_grpc_context());
            // Wrap remote client in a session client
            auto session_sentry_client = std::make_shared<SessionSentryClient>(
                remote_sentry_client,
                eth_status_data_provider);
            clients.push_back(session_sentry_client);
        }

        if (clients.size() == 1) {
            sentry_client = clients[0];
        } else {
            sentry_client = std::make_shared<MultiSentryClient>(std::move(clients));
        }
    }

    return {sentry_client, sentry_server};
}

}  // namespace silkworm::sentry
