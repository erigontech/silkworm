/*
    Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/buildinfo.h>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/concurrency/signal_handler.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/sync_loop.hpp>

#include "common.hpp"

#if defined(_WIN32)
#include <Psapi.h>
#endif

#if defined(__linux__)
#include <fstream>
#include <regex>
#endif

using namespace silkworm;

size_t get_mem_usage() {
    size_t ret{0};
#if defined(_WIN32)

    static HANDLE phandle{GetCurrentProcess()};
    PROCESS_MEMORY_COUNTERS_EX pmc;
    (void)K32GetProcessMemoryInfo(phandle, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    ret = pmc.WorkingSetSize;

#endif

#if defined(__linux__)

    static const std::regex pattern{R"(^VmRSS:\s*(\d*)\s*kB$)", std::regex_constants::icase};
    std::smatch matches;
    std::string line;
    std::ifstream input("/proc/self/status");
    while (std::getline(input, line)) {
        if (std::regex_search(line, matches, pattern, std::regex_constants::match_default)) {
            std::string int_part = matches[1].str();
            auto value{std::strtoull(int_part.c_str(), nullptr, 10)};
            ret = value * 1_Kibi;
            break;
        }
    }

#endif
    return ret;
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

        // Output BuildInfo
        auto build_info{silkworm_get_buildinfo()};
        log::Message(
            "Silkworm",
            {
                "version", build_info->project_version,  //
                "build",
                std::string(build_info->system_name) + "-" + std::string(build_info->system_processor) + " " +
                    std::string(build_info->build_type),                                                            //
                "compiler", std::string(build_info->compiler_id) + " " + std::string(build_info->compiler_version)  //
            });

        // Check db
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
        auto start_time{std::chrono::steady_clock::now()};
        stagedsync::SyncLoop sync_loop(&node_settings, &chaindata_env);
        sync_loop.start(/*wait=*/false);

        // Keep waiting till sync_loop stops
        // Signals are handled in sync_loop and below
        auto t1{std::chrono::steady_clock::now()};
        while (sync_loop.get_state() != Worker::State::kStopped) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            // Check signals
            if (SignalHandler::signalled()) {
                sync_loop.stop(true);
                continue;
            }

            auto t2{std::chrono::steady_clock::now()};
            if ((t2 - t1) > std::chrono::seconds(60)) {
                t1 = std::chrono::steady_clock::now();
                auto total_duration{t1 - start_time};
                log::Info("Resource usage",
                          {
                              "mem", human_size(get_mem_usage()),                                     //
                              "chain", human_size(node_settings.data_directory->chaindata().size()),  //
                              "etl-tmp", human_size(node_settings.data_directory->etl().size()),      //
                              "uptime", StopWatch::format(total_duration)                             //
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
