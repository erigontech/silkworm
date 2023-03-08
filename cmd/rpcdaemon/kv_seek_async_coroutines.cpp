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

#include <silkworm/silkrpc/config.hpp>

#include <functional>
#include <iomanip>
#include <iostream>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <grpcpp/grpcpp.h>
#include <silkworm/core/common/util.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/ethdb/kv/remote_database.hpp>

using silkrpc::LogLevel;

boost::asio::awaitable<void> kv_seek(silkrpc::ethdb::Database& kv_db, const std::string& table_name, const silkworm::Bytes& key) {
    const auto kv_transaction = co_await kv_db.begin();
    std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n" << std::flush;
    const auto kv_cursor = co_await kv_transaction->cursor(table_name);
    auto cursor_id = kv_cursor->cursor_id();
    std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n" << std::flush;
    std::cout << "KV Tx SEEK -> cursor: " << cursor_id << " key: " << key << "\n" << std::flush;
    auto kv_pair = co_await kv_cursor->seek(key);
    std::cout << "KV Tx SEEK <- key: " << kv_pair.key << " value: " << kv_pair.value << "\n" << std::flush;
    std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n" << std::flush;
    co_await kv_transaction->close();
    std::cout << "KV Tx CLOSE <- cursor: 0\n" << std::flush;
    co_return;
}

int kv_seek_async_coroutines(const std::string& target, const std::string& table_name, const silkworm::Bytes& key, uint32_t timeout) {
    try {
        // TODO(canepat): handle also secure channel for remote
        silkrpc::ChannelFactory create_channel = [&]() {
            return grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
        };
        // TODO(canepat): handle also local (shared-memory) database
        silkrpc::ContextPool context_pool{1, create_channel};
        auto& context = context_pool.next_context();
        auto io_context = context.io_context();
        auto& database = context.database();

        boost::asio::co_spawn(*io_context, kv_seek(*database, table_name, key), [&](std::exception_ptr exptr) {
            context_pool.stop();
        });

        context_pool.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n" << std::flush;
    } catch (...) {
        std::cerr << "Unexpected exception\n" << std::flush;
    }

    return 0;
}
