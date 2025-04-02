// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <functional>
#include <future>
#include <iomanip>
#include <iostream>

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/strings/match.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/grpc/client/remote_client.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>

using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::rpc;

ABSL_FLAG(std::string, target, std::string{kDefaultPrivateApiAddr}, "server location as string <address>:<port>");
// ABSL_FLAG(LogLevel, log_verbosity, LogLevel::Critical, "logging level");

Task<std::optional<uint64_t>> latest_block(db::kv::api::Service& service) {
    std::optional<uint64_t> block_num;

    const auto db_transaction = co_await service.begin_transaction();
    try {
        const auto chain_storage{db_transaction->make_storage()};
        db::kv::api::CoherentStateCache state_cache;
        const BlockReader block_reader{*chain_storage, *db_transaction};
        block_num = co_await block_reader.get_latest_block_num();
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
    } catch (...) {
        SILK_ERROR << "unexpected exception";
    }
    co_await db_transaction->close();

    co_return block_num;
}

std::optional<uint64_t> get_latest_block(boost::asio::io_context& ioc, db::kv::api::Service& service) {
    auto result = boost::asio::co_spawn(
        ioc,
        [&]() -> Task<std::optional<uint64_t>> {
            const auto block_num = co_await latest_block(service);
            ioc.stop();
            co_return block_num;
        },
        boost::asio::use_future);
    return result.get();
}

int main(int argc, char* argv[]) {
    absl::SetProgramUsageMessage("Get latest block in Silkworm/Erigon");
    absl::ParseCommandLine(argc, argv);

    log::set_verbosity(log::Level::kCritical);

    try {
        auto target{absl::GetFlag(FLAGS_target)};
        if (target.empty() || !absl::StrContains(target, ":")) {
            std::cerr << "Parameter target is invalid: [" << target << "]\n";
            std::cerr << "Use --target flag to specify the location of Silkworm/Erigon running instance\n";
            return -1;
        }

        // TODO(canepat): handle also secure channel for remote
        ChannelFactory create_channel = [&]() {
            return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
        };
        // TODO(canepat): handle also local (shared-memory) database
        ClientContextPool context_pool{1};
        auto& context = context_pool.next_context();
        auto* ioc = context.ioc();
        auto& grpc_context = *context.grpc_context();

        kv::api::CoherentStateCache state_cache;
        auto channel = ::grpc::CreateChannel(target, ::grpc::InsecureChannelCredentials());
        auto backend = std::make_unique<rpc::ethbackend::RemoteBackEnd>(channel, grpc_context);
        auto database = std::make_unique<db::kv::grpc::client::RemoteClient>(
            create_channel, grpc_context, &state_cache, ethdb::kv::make_backend_providers(backend.get()));

        auto context_pool_thread = std::thread([&]() { context_pool.run(); });

        const auto latest_block_num = get_latest_block(*ioc, *database->service());
        if (latest_block_num) {
            std::cout << "latest_block_num: " << latest_block_num.value() << "\n";
        }

        if (context_pool_thread.joinable()) {
            context_pool_thread.join();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "Unexpected exception\n";
    }

    return 0;
}
