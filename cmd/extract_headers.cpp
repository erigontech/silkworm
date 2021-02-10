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
#include <iostream>
#include <chrono>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/filesystem.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/types/transaction.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/chain/config.hpp>

using namespace silkworm;

// Definitions
using Hash = std::string;           // todo: provide correct definition
using Header = std::string;         // todo: provide correct definition
using BlockNum = uint64_t;          // todo: provide correct definition

bool is_common(Hash h) {return h.length() % 2 == 0;}   // todo: provide correct implementation
std::string rlp_encode_base64(Header hd) {return hd;}  // todo: provide correct implementation
long time(Header) {return 0;}                          // todo: provide correct implementation

class Db {                                  // todo: provide correct implementation
    std::string sb_path;
  public:
    Db(std::string sb_path): sb_path{sb_path} {}

    Hash read_canonical_hash(BlockNum b)    {return "canonical-hash-of-block-" + std::to_string(b);}
    Hash read_head_header_hash()            {return "head-header-hash";}

    Header read_header(Hash h, BlockNum b)  {return "header-of-hash-" + h + "-and-block-" + std::to_string(b);}
    Header read_header(Hash h)              {return "header-of-hash-" + h;}

    //namespace fs = boost::filesystem;

    /* examples
    fs::path datadir(db_path);
    lmdb::DatabaseConfig db_config{db_path};
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};
    auto bodies_table{txn->open(db::table::kBlockBodies)};
    auto tx_lookup_table{txn->open(db::table::kTxLookup)};
    auto transactions_table{txn->open(db::table::kEthTx)};
    uint64_t expected_block_number{0};
    Bytes buffer{}; // To extract compacted data
    */
};

class HeaderListFile {
  public:
    HeaderListFile(std::string file_name) {
        output_file.open(file_name);
    }
    void add_header(const std::string& header) {
        if (empty)
            output_file << template_begin(); // write first part of the template
        else
            output_file << ",\n"; // terminate last line

        output_file << "    \"" << header << "\""; // output the header

        empty = false;
    }
    ~HeaderListFile() {
        if (!empty)
            output_file << "\n"  // terminate last line
                        << template_end(); // write final part of the template
        output_file.close();
    }
  private:
    std::string template_begin() {std::size_t pos = file_template.find('@'); return file_template.substr (0, pos);}
    std::string template_end() {std::size_t pos = file_template.find('@'); return file_template.substr (pos + 1);}

    std::ofstream output_file;
    bool empty = true;

    std::string file_template =
    R"TEMPLATE(
    // hard coded headers
    #include <silkworm/db/header_download.hpp> // ?

    const char* hard_coded_headers[] = {   // "header1"; "header2"; ...
        @
    };
    )TEMPLATE";     // improvement: handle whitespaces here and at add_header()
};

// Main
int main(int argc, char* argv[]) {
    using std::string, std::cout;
    using namespace std::chrono;

    // Command line parsing
    CLI::App app{"Extract Headers. Hard-code historical headers, from block zero to the current block with a certain step"};

    string file_name = "hard_coded_headers.h";
    string db_path = db::default_path();
    uint64_t block_step = 100'000u;     // todo: uint64_t o BlockNum?

    app.add_option("-n,--name,name", file_name, "Name of the output file", true);
        // also accepted as a positional
    app.add_option("-d,--datadir", db_path, "Path to the chain database", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("-s,--step", block_step, "Block step", true)
        ->check(CLI::Range(uint64_t{1}, UINT64_MAX));

    CLI11_PARSE(app, argc, argv);

    // Main loop
    Db db{db_path};
    HeaderListFile output{file_name};

    BlockNum block_num = 0;
    for(; block_num < UINT64_MAX; block_num += block_step) {
        Hash hash = db.read_canonical_hash(block_num);
        if (is_common(hash))
            break;
        Header header = db.read_header(hash, block_num);
        string encoded_header = rlp_encode_base64(header);
        output.add_header(encoded_header);
    }

    // Final tasks
    cout << "Last block is " << block_num << "\n";

    Hash hash = db.read_head_header_hash();
    Header header = db.read_header(hash);

    auto unix_timestamp = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    cout << "Latest header timestamp: " << time(header) << ", current time: " << unix_timestamp << "\n";
}


