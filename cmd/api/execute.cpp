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
const char* kSilkwormInitSymbol = "silkworm_init";
const char* kSilkwormAddSnapshotSymbol = "silkworm_add_snapshot";
const char* kSilkwormExecuteBlocksSymbol = "silkworm_execute_blocks";
const char* kSilkwormFiniSymbol = "silkworm_fini";

//! Function signature for silkworm_init C API
using SilkwormInitSig = int(SilkwormHandle**);

//! Function signature for silkworm_add_snapshot C API
using SilkwormAddSnapshotSig = int(SilkwormHandle*, SilkwormChainSnapshot*);

//! Function signature for silkworm_execute_blocks C API
using SilkwormExecuteBlocksSig =
    int(SilkwormHandle*, MDBX_txn*, uint64_t, uint64_t, uint64_t, uint64_t, bool, uint64_t*, int*);

//! Function signature for silkworm_fini C API
using SilkwormFiniSig = int(SilkwormHandle*);

constexpr const char* kHeader1{"/Users/tullio/Library/Silkworm/snapshots/v1-000000-000500-headers.seg"};
constexpr const char* kBody1{"/Users/tullio/Library/Silkworm/snapshots/v1-000000-000500-bodies.seg"};
constexpr const char* kTransaction1{"/Users/tullio/Library/Silkworm/snapshots/v1-000000-000500-transactions.seg"};

int main(int /*argc*/, char* /*argv*/[]) {
    CLI::App app{"Execute blocks"};

    try {
        const auto pid = boost::this_process::get_id();
        std::cout << "Execute blocks starting [pid=" << std::to_string(pid) << "]\n";
        // parse_command_line(argc, argv, app, settings);

        // Import the silkworm_init symbol from silkworm API library
        const auto silkworm_init{
            boost::dll::import_symbol<SilkwormInitSig>(kSilkwormApiLibPath, kSilkwormInitSymbol)};

        // Import the silkworm_add_snapshot symbol from silkworm API library
        const auto silkworm_add_snapshot{
            boost::dll::import_symbol<SilkwormAddSnapshotSig>(kSilkwormApiLibPath, kSilkwormAddSnapshotSymbol)};

        // Import the silkworm_execute_blocks symbol from silkworm API library
        const auto silkworm_execute_blocks{
            boost::dll::import_symbol<SilkwormExecuteBlocksSig>(kSilkwormApiLibPath, kSilkwormExecuteBlocksSymbol)};

        // Import the silkworm_fini symbol from silkworm API library
        const auto silkworm_fini{
            boost::dll::import_symbol<SilkwormFiniSig>(kSilkwormApiLibPath, kSilkwormFiniSymbol)};

        // Initialize SilkwormAPI library
        SilkwormHandle* handle{nullptr};
        const int init_status_code = silkworm_init(&handle);
        if (init_status_code != SILKWORM_OK) {
            std::cerr << "Execute blocks silkworm_init failed [code=" << std::to_string(init_status_code) << "]\n";
            return init_status_code;
        }

        // Add snapshots to SilkwormAPI library
        SilkwormChainSnapshot chain_snapshot{
            .headers{
                .segment{
                    .file_path = kHeader1,
                    .memory_address = 0,
                    .memory_length = 0,
                },
                .header_hash_index{
                    .file_path = "",
                    .memory_address = 0,
                    .memory_length = 0,
                }},
            .bodies{
                .segment{
                    .file_path = kBody1,
                    .memory_address = 0,
                    .memory_length = 0,
                },
                .block_num_index{
                    .file_path = "",
                    .memory_address = 0,
                    .memory_length = 0,
                }},
            .transactions{
                .segment{
                    .file_path = kTransaction1,
                    .memory_address = 0,
                    .memory_length = 0,
                },
                .tx_hash_index{
                    .file_path = "",
                    .memory_address = 0,
                    .memory_length = 0,
                },
                .tx_hash_2_block_index{
                    .file_path = "",
                    .memory_address = 0,
                    .memory_length = 0,
                }}};
        const int add_snapshot_status_code{silkworm_add_snapshot(handle, &chain_snapshot)};
        if (add_snapshot_status_code != SILKWORM_OK) {
            return init_status_code;
        }

        silkworm::DataDirectory data_dir{};
        silkworm::db::EnvConfig config{
            .path = data_dir.chaindata().path().string(),
            .readonly = false,
            .exclusive = true};
        ::mdbx::env_managed env{silkworm::db::open_env(config)};
        ::mdbx::txn_managed rw_txn{env.start_write()};

        uint64_t last_executed_block{std::numeric_limits<uint64_t>::max()};
        int mdbx_error_code{0};
        const int status_code{
            silkworm_execute_blocks(handle, &*rw_txn, 1, 46147, 46147, 1, false, &last_executed_block, &mdbx_error_code)};
        std::cout << "Execute blocks status code: " << std::to_string(status_code) << "\n";

        // Finalize SilkwormAPI library
        const int fini_status_code = silkworm_fini(handle);
        if (fini_status_code != SILKWORM_OK) {
            std::cerr << "Execute blocks silkworm_fini failed [code=" << std::to_string(fini_status_code) << "]\n";
            return fini_status_code;
        }

        rw_txn.abort();  // We do not want to commit anything now

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
