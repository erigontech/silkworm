/*
   Copyright 2020 The Silkworm Authors

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

#include <functional>
#include <future>
#include <iomanip>
#include <iostream>

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <grpcpp/grpcpp.h>
#include <silkworm/core/common/util.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#include <silkworm/rpc/ethdb/kv/remote_database.hpp>

using namespace silkworm;
using namespace silkworm::rpc;

ABSL_FLAG(std::string, target, kDefaultPrivateApiAddr, "server location as string <address>:<port>");
// ABSL_FLAG(LogLevel, log_verbosity, LogLevel::Critical, "logging level");

Task<std::optional<uint64_t>> latest_block(ethdb::Database& db) {
    std::optional<uint64_t> block_height;

    const auto db_transaction = co_await db.begin();
    try {
        ethdb::TransactionDatabase tx_db_reader{*db_transaction};
        block_height = co_await core::get_latest_block_number(tx_db_reader);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
    } catch (...) {
        SILK_ERROR << "unexpected exception";
    }
    co_await db_transaction->close();

    co_return block_height;
}

std::optional<uint64_t> get_latest_block(boost::asio::io_context& io_context, ethdb::Database& db) {
    auto result = boost::asio::co_spawn(
        io_context,
        [&]() -> Task<std::optional<uint64_t>> {
            const auto block_number = co_await latest_block(db);
            io_context.stop();
            co_return block_number;
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
        if (target.empty() || target.find(":") == std::string::npos) {
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
        auto io_context = context.io_context();

        auto channel{::grpc::CreateChannel(target, ::grpc::InsecureChannelCredentials())};
        auto database = std::make_unique<ethdb::kv::RemoteDatabase>(*context.grpc_context(), channel);

        auto context_pool_thread = std::thread([&]() { context_pool.run(); });

        const auto latest_block_number = get_latest_block(*io_context, *database);
        if (latest_block_number) {
            std::cout << "latest_block_number: " << latest_block_number.value() << "\n" << std::flush;
        }

        if (context_pool_thread.joinable()) {
            context_pool_thread.join();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "Unexpected exception\n" << std::flush;
    }

    return 0;
}
