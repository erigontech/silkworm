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

#include <CLI/CLI.hpp>
#include <boost/filesystem.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/db/bucket.hpp>

#include <string>
#include <csignal>
#include <iostream>

namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{false};
int errorCode{0};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}


int main(int argc, char* argv[]) {
    CLI::App app("Tests db interfaces.");

    std::string po_db_path{silkworm::db::default_path()};
    bool po_debug{false};
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and
    // has some files in it

    bfs::path db_path(po_db_path);
    CLI::Option* db_path_set =
        app.add_option("--db", po_db_path, "Path to chain db", true)->check(CLI::ExistingDirectory);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || db_path.empty()) {
        db_path_set->required();
    }

    app.add_flag("-d,--debug", po_debug, "May be ignored.");

    CLI11_PARSE(app, argc, argv);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    db_path = bfs::path(po_db_path);
    if (db_path.empty()) {
        std::cerr << "Provided --db [" << po_db_path << "] is an empty directory" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    }

    try
    {
        auto env = db::get_env(po_db_path.c_str());
        std::cout << "Database is " << (env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
        {
            auto txn_ro = env->begin_ro_transaction();
            MDB_stat s{};
            auto headers = txn_ro->open_bucket(db::bucket::kBlockHeaders);
            headers->get_stat(&s);
            std::cout << "Headers Table has " << s.ms_entries << " entries" << std::endl;
            auto bodies = txn_ro->open_bucket(db::bucket::kBlockBodies);
            bodies->get_stat(&s);
            std::cout << "Bodies  Table has " << s.ms_entries << " entries" << std::endl;

            size_t totalEntries{s.ms_entries};
            size_t batchEntries{totalEntries / 20};
            uint32_t percent{0};

            auto bodies_cursor = bodies->get_cursor();
            MDB_val key;
            MDB_val data;
            int rc{bodies_cursor->first(&key, &data)};
            while (rc == MDB_SUCCESS)
            {
                batchEntries--;
                if (!batchEntries) {
                    batchEntries = totalEntries / 20;
                    percent += 5;
                    std::cout << "Navigated " << percent << "% of block bodies" << std::endl;
                }
                rc = bodies_cursor->next(&key, &data);
            }

            bodies_cursor->close();
            txn_ro->commit();
        }
        env->close();
        std::cout << "Database is " << (env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
    }
    catch (db::lmdb::exception& ex)
    {
        // This handles specific lmdb errors
        std::cout << ex.what() << " " << ex.err() << std::endl;
    }
    catch (std::runtime_error& ex)
    {
        // This handles runtime ligic errors
        // eg. trying to open two rw txns
        std::cout << ex.what() << std::endl;
    }

    return 0;
}
