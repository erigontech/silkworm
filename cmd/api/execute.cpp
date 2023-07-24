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

#include <iostream>
#include <limits>
#include <stdexcept>

#include <CLI/CLI.hpp>
#include <boost/dll.hpp>
#include <boost/process/environment.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <mdbx.h++>
#pragma GCC diagnostic pop

#include <silkworm/api/silkworm_api.h>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/mdbx.hpp>

const char* kSilkwormApiLibPath = "../../silkworm/api/libsilkworm_api.dylib";
const char* kSilkwormExecuteBlocksSymbol = "silkworm_execute_blocks";

//! Function signature for silkworm_execute_blocks C API
using SilkwormExecuteBlocksSig =
    SilkwormStatusCode(MDBX_txn*, uint64_t, uint64_t, uint64_t, uint64_t, bool, uint64_t*, int*);

int main(int /*argc*/, char* /*argv*/[]) {
    CLI::App app{"Execute blocks"};

    try {
        const auto pid = boost::this_process::get_id();
        std::cout << "Execute blocks starting [pid=" << std::to_string(pid) << "]\n";
        // parse_command_line(argc, argv, app, settings);

        // Import the silkworm_execute_blocks symbol from silkworm API library
        const auto silkworm_execute_blocks{
            boost::dll::import_symbol<SilkwormExecuteBlocksSig>(kSilkwormApiLibPath, kSilkwormExecuteBlocksSymbol)};

        silkworm::DataDirectory data_dir{};
        silkworm::db::EnvConfig config{
            .path = data_dir.chaindata().path().string(),
            .readonly = false,
            .exclusive = true};
        ::mdbx::env_managed env{silkworm::db::open_env(config)};
        ::mdbx::txn_managed rw_txn{env.start_write()};

        uint64_t last_executed_block{std::numeric_limits<uint64_t>::max()};
        int mdbx_error_code{0};
        const auto status_code{
            silkworm_execute_blocks(&*rw_txn, 1, 1, 1, 1, false, &last_executed_block, &mdbx_error_code)};
        std::cout << "Execute blocks status code: " << std::to_string(status_code) << "\n";

        std::cout << "Execute blocks exiting [pid=" << std::to_string(pid) << "]\n";
        return status_code;
    } catch (const CLI::ParseError& pe) {
        return app.exit(pe);
    } catch (const std::exception& e) {
        // SILK_CRIT << "Execute blocks exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        // SILK_CRIT << "Execute blocks exiting due to unexpected exception";
        return -3;
    }
}
