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
#include <boost/endian/conversion.hpp>
#include <boost/beast/core/detail/base64.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/types/transaction.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/chain/config.hpp>

using namespace silkworm;

// Definitions
using Hash = evmc::bytes32; // uint8_t bytes[32], see common/utils.hpp for conversions
using Header = BlockHeader;
using BlockNum = uint64_t;
//using Bytes = std::basic_string<uint8_t>; already defined elsewhere

class Db {
    std::shared_ptr<lmdb::Environment> env;
    std::unique_ptr<lmdb::Transaction> txn;
  public:
    Db(std::string db_path) {
        lmdb::DatabaseConfig db_config{db_path};
        db_config.set_readonly(false);
        env = lmdb::get_env(db_config);
        txn = env->begin_ro_transaction();  // todo: check if ro is ok or we need rw
    }

    std::optional<Hash> read_canonical_hash(BlockNum b) {  // throws db exceptions
        auto header_table = txn->open(db::table::kBlockHeaders);
        // accessing this table with only b we will get the hash of the canonical block at height b
        std::optional<ByteView> hash = header_table->get(db::header_hash_key(b));
        if (!hash) return std::nullopt; // not found
        assert(hash->size() == kHashLength);
        return to_bytes32(hash.value()); // copy
    }

    Bytes head_header_key() {
        std::string table_name = db::table::kHeadHeader.name; // todo: check!
        Bytes key{table_name.begin(), table_name.end()};
        return key;
    }

    std::optional<Hash> read_head_header_hash() {
        auto head_header_table = txn->open(db::table::kHeadHeader);
        std::optional<ByteView> hash = head_header_table->get(head_header_key());
        if (!hash) return std::nullopt; // not found
        assert(hash->size() == kHashLength);
        return to_bytes32(hash.value()); // copy
    }

    std::optional<BlockHeader> read_header(BlockNum b, Hash h)  {
        // auto header_table = txn->open(db::table::kBlockHeaders);
        // std::optional<ByteView> header_rlp = header_table->get(db::block_key(b, h));
        // ... decode header_rlp ...
        // but there is an implementation id db
        return db::read_header(*txn, b, h.bytes);
    }

    std::optional<BlockHeader> read_header(Hash h) {
        auto blockhashes_table = txn->open(db::table::kHeaderNumbers);
        auto encoded_block_num = blockhashes_table->get(h.bytes);
        if (!encoded_block_num) return {};
        BlockNum block_num = boost::endian::load_big_u64(encoded_block_num->data());
        return read_header(block_num, h);
    }
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
    void close() {
        if (!output_file.is_open()) return;
        if (!empty)
            output_file << "\n"  // terminate last line
                        << template_end(); // write final part of the template
        output_file.close();

    }
    ~HeaderListFile() {
        close();
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

std::string base64encode(const ByteView& bytes) {
    size_t encoded_len = boost::beast::detail::base64::encoded_size(bytes.length());
    std::unique_ptr encoded_bytes = std::unique_ptr<char[]>(new char[encoded_len]);
    boost::beast::detail::base64::encode(encoded_bytes.get(), bytes.data(), bytes.length());
    //encoded_bytes[encoded_len] = 0;
    return std::string(encoded_bytes.get(),encoded_len);
}

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
    for (; block_num < UINT64_MAX; block_num += block_step) {
        std::optional<Hash> hash = db.read_canonical_hash(block_num);
        if (!hash) break;
        std::optional<BlockHeader> header = db.read_header(block_num, hash.value());
        if (!hash) throw std::logic_error("header hash without header in db");
        Bytes encoded_header;
        rlp::encode(encoded_header, header.value());
        output.add_header(base64encode(encoded_header));
    }
    output.close();

    // Final tasks
    cout << "Last block is " << block_num << "\n";

    auto hash = db.read_head_header_hash();
    if (!hash) throw std::logic_error("hash of head header not found in db");
    auto header = db.read_header(hash.value());
    if (!header) throw std::logic_error("head header not found in db");

    auto unix_timestamp = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    cout << "Latest header timestamp: " << header->timestamp << ", current time: " << unix_timestamp << "\n";
}


