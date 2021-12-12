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
#include <boost/bind/bind.hpp>

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

void operator delete(void* ptr, size_t size) {
    s_allocated_memory -= size;
    free(ptr);
}

void operator delete[](void* ptr, size_t size) {
    s_allocated_memory -= size;
    free(ptr);
}

int main(int argc, char* argv[]) {
    using namespace boost::placeholders;

    CLI::App cli("Silkworm node");
    cli.get_formatter()->column_width(50);
    int ret{0};

    try {
        log::Settings log_settings{};  // Holds logging settings
        NodeSettings node_settings{};  // Holds node settings

        cmd::parse_silkworm_command_line(cli, argc, argv, log_settings, node_settings);

        SignalHandler::init();    // Trap OS signals
        log::init(log_settings);  // Initialize logging with cli settings

        cmd::run_preflight_checklist(node_settings);  // Prepare database for takeoff

        auto chaindata_env{silkworm::db::open_env(node_settings.chaindata_env_config)};

        // Start sync loop
        stagedysnc::SyncLoop sync_loop(&node_settings, &chaindata_env);
        std::atomic_bool sync_loop_terminated{false};
        std::mutex sync_loop_mtx;
        std::condition_variable sync_loop_terminated_cv{};
        std::function<void(Worker * sender)> sync_loop_terminated_cb = [&sync_loop_terminated,
                                                                        &sync_loop_terminated_cv](Worker*) -> void {
            sync_loop_terminated.store(true);
            sync_loop_terminated_cv.notify_all();
        };
        auto sync_loop_terminated_connector =
            sync_loop.signal_stopped.connect(boost::bind<void>(sync_loop_terminated_cb, _1));

        sync_loop.start(/*wait=*/true);

        // Wait till sync_loop completes
        // do other stuff meanwhile in this thread like compute total memory consumption
        // and/or cpu load and/or, again, total number of connected peers
        bool expected_status{true};
        while (!sync_loop_terminated.compare_exchange_strong(expected_status, false)) {
            expected_status = true;
            {
                std::unique_lock l(sync_loop_mtx);
                if (sync_loop_terminated_cv.wait_for(l, std::chrono::seconds(30)) ==
                    std::cv_status::no_timeout) {
                    continue;
                }
            }

            // The previous wait has timed-out without notification, so we can proceed with
            // timed logging
            log::Info() << kColorGreenHigh << "Memory allocation " << kColorWhiteHigh << human_size(s_allocated_memory.load())
                        << kColorGreenHigh << "  Etl temp size " << kColorWhiteHigh << human_size(node_settings.data_directory->etl().size())
                        << kColorGreenHigh << "  Chaindata size " << kColorWhiteHigh << human_size(node_settings.data_directory->chaindata().size());
        }

        if (sync_loop.has_exception()) {
            ret = -1;
        }

        log::Message() << "Closing Database chaindata path " << node_settings.data_directory->chaindata().path();
        chaindata_env.close();

    } catch (const CLI::ParseError& ex) {
        return cli.exit(ex);
    } catch (const std::runtime_error& ex) {
        log::Error() << ex.what();
        ret = -1;
    } catch (const std::invalid_argument& ex) {
        std::cerr << "\tInvalid argument :" << ex.what() << "\n" << std::endl;
        ret = -3;
    } catch (const std::exception& ex) {
        std::cerr << "\tUnexpected error : " << ex.what() << "\n" << std::endl;
        ret = -4;
    } catch (...) {
        std::cerr << "\tUnexpected undefined error\n" << std::endl;
        ret = -99;
    }

    return ret;
}
