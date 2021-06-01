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

#include <CLI/CLI.hpp>

#include <silkworm/db/util.hpp>

int main(int argc, char* argv[]) {
    CLI::App app{"Generate account & storage tries in the DB and compute the state root"};

    using namespace silkworm;

    std::string db_path{db::default_path()};
    app.add_option("--chaindata", db_path, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    CLI11_PARSE(app, argc, argv);

    // TODO(Andrew) implement
}
