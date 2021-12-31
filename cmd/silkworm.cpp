/*
    Copyright 2021 The Silkworm Authors

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

#include <optional>
#include <regex>

#include <CLI/CLI.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/common/signal_handler.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/sync_loop.hpp>

#include "common.hpp"

using namespace silkworm;

static std::atomic<size_t> s_allocated_memory{0};

void* operator new(size_t size) {
    s_allocated_memory += size;
    return malloc(size);
}

void* operator new[](size_t size) {
    s_allocated_memory += size;
    return malloc(size);
}

void operator delete(void* ptr, size_t size) noexcept {
    s_allocated_memory -= size;
    free(ptr);
}

void operator delete[](void* ptr, size_t size) noexcept {
    s_allocated_memory -= size;
    free(ptr);
}

void operator delete(void* ptr) noexcept {
    s_allocated_memory -= sizeof(ptr);
    free(ptr);
}

void operator delete[](void* ptr) noexcept {
    s_allocated_memory -= sizeof(ptr);
    free(ptr);
}

int main(int argc, char* argv[]) {
    using namespace boost::placeholders;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);

    try {
        log::Settings log_settings{};  // Holds logging settings
        NodeSettings node_settings{};  // Holds node settings

        cmd::parse_silkworm_command_line(cli, argc, argv, log_settings, node_settings);

        SignalHandler::init();    // Trap OS signals
        log::init(log_settings);  // Initialize logging with cli settings

        cmd::run_preflight_checklist(node_settings);  // Prepare database for takeoff

        auto chaindata_env{silkworm::db::open_env(node_settings.chaindata_env_config)};

        // Start boost asio
        using asio_guard_type = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
        auto asio_guard = std::make_unique<asio_guard_type>(node_settings.asio_context.get_executor());
        std::thread asio_thread{[&node_settings]() -> void {
            log::Trace("Boost Asio", {"state", "started"});
            node_settings.asio_context.run();
            log::Trace("Boost Asio", {"state", "stopped"});
        }};

        // Start sync loop
        stagedysnc::SyncLoop sync_loop(&node_settings, &chaindata_env);
        sync_loop.start(/*wait=*/false);

        // Keep waiting till sync_loop stops
        // Signals are handled in sync_loop and below
        auto t1{std::chrono::steady_clock::now()};
        while (sync_loop.get_state() != Worker::State::kStopped) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto t2{std::chrono::steady_clock::now()};
            if ((t2 - t1) > std::chrono::seconds(60)) {
                t1 = std::chrono::steady_clock::now();
                log::Info("Resource usage",
                          {
                              "alloc", human_size(s_allocated_memory.load()),                         //
                              "chain", human_size(node_settings.data_directory->chaindata().size()),  //
                              "etl-tmp", human_size(node_settings.data_directory->etl().size())       //
                          });
            }
        }

        asio_guard.reset();
        asio_thread.join();

        log::Message() << "Closing Database chaindata path " << node_settings.data_directory->chaindata().path();
        chaindata_env.close();
        sync_loop.rethrow();  // Eventually throws the exception which caused the stop
        return 0;

    } catch (const CLI::ParseError& ex) {
        return cli.exit(ex);
    } catch (const std::runtime_error& ex) {
        log::Error() << ex.what();
        return -1;
    } catch (const std::invalid_argument& ex) {
        std::cerr << "\tInvalid argument :" << ex.what() << "\n" << std::endl;
        return -3;
    } catch (const std::exception& ex) {
        std::cerr << "\tUnexpected error : " << ex.what() << "\n" << std::endl;
        return -4;
    } catch (...) {
        std::cerr << "\tUnexpected undefined error\n" << std::endl;
        return -99;
    }
}
