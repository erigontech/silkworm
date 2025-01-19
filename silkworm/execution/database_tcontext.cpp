/*
   Copyright 2025 The Silkworm Authors

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

#include "database_tcontext.hpp"

#include <fstream>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::execution {

using namespace silkworm::datastore::kvdb;

std::filesystem::path get_tests_dir() {
    auto working_dir = std::filesystem::current_path();

    while (working_dir != "/") {
        if (std::filesystem::exists(working_dir / "third_party" / "execution-apis")) {
            return working_dir / "third_party" / "execution-apis" / "tests";
        }

        if (std::filesystem::exists(working_dir / "silkworm" / "third_party" / "execution-apis")) {
            return working_dir / "silkworm" / "third_party" / "execution-apis" / "tests";
        }

        if (std::filesystem::exists(working_dir / "project" / "third_party" / "execution-apis")) {
            return working_dir / "project" / "third_party" / "execution-apis" / "tests";
        }

        working_dir = working_dir.parent_path();
    }

    throw std::logic_error("Failed to find tests directory");
}

InMemoryState populate_genesis(RWTxn& txn, const std::filesystem::path& tests_dir) {
    auto genesis_json_path = tests_dir / "genesis.json";
    std::ifstream genesis_json_input_file(genesis_json_path);
    nlohmann::json genesis_json;
    genesis_json_input_file >> genesis_json;

    InMemoryState state = read_genesis_allocation(genesis_json.at("alloc"));
    silkworm::db::write_genesis_allocation_to_db(txn, state);

    BlockHeader header{read_genesis_header(genesis_json, state.state_root_hash())};
    BlockBody block_body{
        .withdrawals = std::vector<silkworm::Withdrawal>{0},
    };

    // FIX 2: set empty receipts root, should be done in the main code, requires https://github.com/erigontech/silkworm/issues/1348
    header.withdrawals_root = kEmptyRoot;

    auto block_hash{header.hash()};
    auto block_hash_key{silkworm::db::block_key(header.number, block_hash.bytes)};
    silkworm::db::write_header(txn, header, /*with_header_numbers=*/true);            // Write table::kHeaders and table::kHeaderNumbers
    silkworm::db::write_canonical_header_hash(txn, block_hash.bytes, header.number);  // Insert header hash as canonical
    silkworm::db::write_total_difficulty(txn, block_hash_key, header.difficulty);     // Write initial difficulty

    silkworm::db::write_body(txn, block_body, block_hash.bytes, header.number);  // Write block body (empty)
    silkworm::db::write_head_header_hash(txn, block_hash.bytes);                 // Update head header in config

    const uint8_t genesis_null_receipts[] = {0xf6};  // <- cbor encoded
    open_cursor(txn, silkworm::db::table::kBlockReceipts)
        .upsert(datastore::kvdb::to_slice(block_hash_key).safe_middle(0, 8), datastore::kvdb::to_slice(Bytes(genesis_null_receipts, 1)));

    // Write Chain Settings
    auto config_data{genesis_json["config"].dump()};
    open_cursor(txn, silkworm::db::table::kConfig)
        .upsert(to_slice(ByteView{block_hash.bytes}), mdbx::slice{config_data.data()});

    return state;
}

void populate_blocks(RWTxn& txn, const std::filesystem::path& tests_dir, InMemoryState& state_buffer) {
    auto rlp_path = tests_dir / "chain.rlp";
    std::ifstream file(rlp_path, std::ios::binary);
    if (!file) {
        throw std::logic_error("Failed to open the file: " + rlp_path.string());
    }
    std::vector<Bytes> rlps;
    std::vector<uint8_t> line;

    Bytes rlp_buffer(std::istreambuf_iterator<char>(file), {});
    file.close();
    ByteView rlp_view{rlp_buffer};

    auto chain_config = silkworm::db::read_chain_config(txn);

    if (!chain_config.has_value()) {
        throw std::logic_error("Failed to read chain config");
    }
    auto rule_set = protocol::rule_set_factory(*chain_config);

    while (!rlp_view.empty()) {
        silkworm::Block block;

        if (!silkworm::rlp::decode(rlp_view, block, silkworm::rlp::Leftover::kAllow)) {
            throw std::logic_error("Failed to decode RLP file");
        }

        // store original hashes
        auto block_hash = block.header.hash();
        auto block_hash_key = silkworm::db::block_key(block.header.number, block_hash.bytes);

        // FIX 3: populate senders table
        silkworm::db::write_senders(txn, block_hash, block.header.number, block);

        // FIX 4a: populate tx lookup table and create receipts
        silkworm::db::write_tx_lookup(txn, block);

        // FIX 4b: populate receipts and logs table
        std::vector<silkworm::Receipt> receipts;
        ExecutionProcessor processor{block, *rule_set, state_buffer, *chain_config, true};
        silkworm::db::Buffer db_buffer{txn, std::make_unique<silkworm::db::BufferROTxDataModel>(txn)};
        for (auto& block_txn : block.transactions) {
            silkworm::Receipt receipt{};
            processor.execute_transaction(block_txn, receipt);
            receipts.emplace_back(receipt);
        }
        processor.evm().state().write_to_db(block.header.number);
        db_buffer.insert_receipts(block.header.number, receipts);
        db_buffer.write_history_to_db();

        // FIX 5: insert system transactions
        intx::uint256 max_priority_fee_per_gas = block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_priority_fee_per_gas;
        intx::uint256 max_fee_per_gas = block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_fee_per_gas;
        silkworm::Transaction system_transaction;
        system_transaction.max_priority_fee_per_gas = max_priority_fee_per_gas;
        system_transaction.max_fee_per_gas = max_fee_per_gas;
        block.transactions.emplace(block.transactions.begin(), system_transaction);
        block.transactions.emplace_back(system_transaction);

        silkworm::db::write_header(txn, block.header, /*with_header_numbers=*/true);            // Write table::kHeaders and table::kHeaderNumbers
        silkworm::db::write_canonical_header_hash(txn, block_hash.bytes, block.header.number);  // Insert header hash as canonical

        // TODO: find how to decode total difficulty
        // write_total_difficulty(txn, block_hash_key, block.header.difficulty);     // Write initial difficulty
        silkworm::db::write_total_difficulty(txn, block_hash_key, 1);  // Write initial difficulty

        silkworm::db::write_raw_body(txn, block, block_hash, block.header.number);
        silkworm::db::write_head_header_hash(txn, block_hash.bytes);  // Update head header in config
        silkworm::db::write_last_head_block(txn, block_hash);         // Update head block in config
        silkworm::db::write_last_safe_block(txn, block_hash);         // Update last safe block in config
        silkworm::db::write_last_finalized_block(txn, block_hash);    // Update last finalized block in config
    }
}

namespace {
    mdbx::env_managed initialize_test_database(const std::filesystem::path& chaindata_dir_path) {
        const auto tests_dir = get_tests_dir();

        EnvConfig env_config{
            .path = chaindata_dir_path.string(),
            .create = true,
            .exclusive = true,
            .in_memory = true,
            .shared = false,
        };
        auto env = open_env(env_config);

        RWTxnManaged txn{env};
        silkworm::db::table::check_or_create_chaindata_tables(txn);
        auto state_buffer = populate_genesis(txn, tests_dir);
        populate_blocks(txn, tests_dir, state_buffer);
        txn.commit_and_stop();

        return env;
    }

}  // namespace

TestDatabaseContext::TestDatabaseContext(const TemporaryDirectory& tmp_dir)
    : chaindata_dir_path_{DataDirectory{tmp_dir.path()}.chaindata().path()},
      env_{std::make_unique<mdbx::env_managed>(initialize_test_database(chaindata_dir_path_))} {}

silkworm::ChainConfig TestDatabaseContext::get_chain_config() const {
    ROTxnManaged txn = chaindata().start_ro_tx();
    auto chain_config = silkworm::db::read_chain_config(txn);
    return chain_config ? *chain_config : silkworm::ChainConfig{};
}

}  // namespace silkworm::execution
