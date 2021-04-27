/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "access_layer.hpp"

#include <cassert>

#include <boost/endian/conversion.hpp>
#include <nlohmann/json.hpp>

#include "bitmap.hpp"
#include "tables.hpp"

namespace silkworm::db {

std::optional<BlockHeader> read_header(lmdb::Transaction& txn, uint64_t block_number,
                                       const uint8_t (&hash)[kHashLength]) {
    auto table{txn.open(table::kHeaders)};
    std::optional<ByteView> rlp{table->get(block_key(block_number, hash))};
    if (!rlp) {
        return std::nullopt;
    }

    BlockHeader header;
    rlp::err_handler(rlp::decode(*rlp, header));
    return header;
}

std::optional<intx::uint256> read_total_difficulty(lmdb::Transaction& txn, uint64_t block_number,
                                                   const uint8_t (&hash)[kHashLength]) {
    auto table{txn.open(table::kDifficulty)};
    std::optional<ByteView> rlp{table->get(block_key(block_number, hash))};
    if (!rlp) {
        return std::nullopt;
    }

    intx::uint256 td{0};
    rlp::err_handler(rlp::decode(*rlp, td));
    return td;
}

// TG ReadTransactions
static std::vector<Transaction> read_transactions(lmdb::Transaction& txn, uint64_t base_id, uint64_t count) {
    if (!count) {
        return {};
    }

    auto table{txn.open(table::kEthTx)};
    return read_transactions(*table, base_id, count);
}

std::vector<Transaction> read_transactions(lmdb::Table& txn_table, uint64_t base_id, uint64_t count) {
    std::vector<Transaction> v;
    if (count == 0) {
        return v;
    }
    v.reserve(count);

    Bytes txn_key(8, '\0');
    boost::endian::store_big_u64(txn_key.data(), base_id);
    MDB_val key_mdb{to_mdb_val(txn_key)};
    MDB_val data_mdb{};

    uint64_t i{0};
    for (int rc{txn_table.seek_exact(&key_mdb, &data_mdb)}; rc != MDB_NOTFOUND && i < count;
         rc = txn_table.get_next(&key_mdb, &data_mdb), ++i) {
        lmdb::err_handler(rc);
        ByteView data{from_mdb_val(data_mdb)};

        Transaction eth_txn;
        rlp::err_handler(rlp::decode(data, eth_txn));
        v.push_back(eth_txn);
    }

    return v;
}

std::optional<BlockWithHash> read_block(lmdb::Transaction& txn, uint64_t block_number, bool read_senders) {
    auto canonical_table{txn.open(table::kCanonicalHashes)};
    std::optional<ByteView> hash{canonical_table->get(block_key(block_number))};
    if (!hash) {
        return std::nullopt;
    }

    BlockWithHash bh{};
    assert(hash->size() == kHashLength);
    std::memcpy(bh.hash.bytes, hash->data(), kHashLength);

    Bytes key{block_key(block_number, bh.hash.bytes)};
    auto header_table{txn.open(table::kHeaders)};
    std::optional<ByteView> header_rlp{header_table->get(key)};
    if (!header_rlp) {
        return std::nullopt;
    }

    rlp::err_handler(rlp::decode(*header_rlp, bh.block.header));

    std::optional<BlockBody> body{read_body(txn, block_number, bh.hash.bytes, read_senders)};
    if (!body) {
        return std::nullopt;
    }

    bh.block.ommers = body->ommers;
    bh.block.transactions = body->transactions;

    return bh;
}

std::optional<BlockBody> read_body(lmdb::Transaction& txn, uint64_t block_number, const uint8_t (&hash)[kHashLength],
                                   bool read_senders) {
    Bytes key{block_key(block_number, hash)};

    auto body_table{txn.open(table::kBlockBodies)};
    std::optional<ByteView> body_rlp{body_table->get(key)};
    if (!body_rlp) {
        return std::nullopt;
    }

    auto body{detail::decode_stored_block_body(*body_rlp)};

    BlockBody out;
    out.ommers = body.ommers;
    out.transactions = read_transactions(txn, body.base_txn_id, body.txn_count);

    if (read_senders) {
        std::vector<evmc::address> senders{db::read_senders(txn, block_number, hash)};
        if (senders.size() != out.transactions.size()) {
            throw MissingSenders("senders count does not match transactions count");
        }
        for (size_t i{0}; i < senders.size(); ++i) {
            out.transactions[i].from = senders[i];
        }
    }

    return out;
}

std::vector<evmc::address> read_senders(lmdb::Transaction& txn, int64_t block_number,
                                        const uint8_t (&hash)[kHashLength]) {
    std::vector<evmc::address> senders{};
    auto table{txn.open(table::kSenders)};
    std::optional<ByteView> data{table->get(block_key(block_number, hash))};
    if (!data) {
        return senders;
    }

    assert(data->length() % kAddressLength == 0);
    senders.resize(data->length() / kAddressLength);
    std::memcpy(senders.data(), data->data(), data->size());
    return senders;
}

std::optional<Bytes> read_code(lmdb::Transaction& txn, const evmc::bytes32& code_hash) {
    auto table{txn.open(table::kCode)};
    std::optional<ByteView> val{table->get(full_view(code_hash))};
    if (!val) {
        return {};
    }
    return Bytes{*val};
}

// TG FindByHistory for account
static std::optional<ByteView> historical_account(lmdb::Transaction& txn, const evmc::address& address,
                                                  uint64_t block_number) {
    auto history_table{txn.open(table::kAccountHistory)};
    std::optional<Entry> entry{history_table->seek(account_history_key(address, block_number))};
    if (!entry) {
        return std::nullopt;
    }

    if (!has_prefix(entry->key, full_view(address))) {
        return std::nullopt;
    }

    auto bitmap{bitmap::read(entry->value)};

    auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    auto change_table{txn.open(table::kPlainAccountChangeSet)};
    return change_table->get(block_key(*change_block), full_view(address));
}

// TG FindByHistory for storage
static std::optional<ByteView> historical_storage(lmdb::Transaction& txn, const evmc::address& address,
                                                  uint64_t incarnation, const evmc::bytes32& location,
                                                  uint64_t block_number) {
    auto history_table{txn.open(table::kStorageHistory)};
    std::optional<Entry> entry{history_table->seek(storage_history_key(address, location, block_number))};
    if (!entry) {
        return std::nullopt;
    }

    ByteView k{entry->key};
    if (k.substr(0, kAddressLength) != full_view(address) ||
        k.substr(kAddressLength, kHashLength) != full_view(location)) {
        return std::nullopt;
    }

    auto bitmap{bitmap::read(entry->value)};

    auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    auto change_table{txn.open(table::kPlainStorageChangeSet)};
    return change_table->get(storage_change_key(*change_block, address, incarnation), full_view(location));
}

std::optional<Account> read_account(lmdb::Transaction& txn, const evmc::address& address,
                                    std::optional<uint64_t> block_num) {
    std::optional<ByteView> encoded{};
    if (block_num) {
        encoded = historical_account(txn, address, *block_num);
    }
    if (!encoded) {
        auto state_table{txn.open(table::kPlainState)};
        encoded = state_table->get(full_view(address));
    }
    if (!encoded || encoded->empty()) {
        return {};
    }

    auto [acc, err]{decode_account_from_storage(*encoded)};
    rlp::err_handler(err);

    if (acc.incarnation > 0 && acc.code_hash == kEmptyHash) {
        // restore code hash
        auto code_hash_table{txn.open(table::kPlainContractCode)};
        std::optional<ByteView> hash{code_hash_table->get(storage_prefix(address, acc.incarnation))};
        if (hash && hash->length() == kHashLength) {
            std::memcpy(acc.code_hash.bytes, hash->data(), kHashLength);
        }
    }

    return acc;
}

evmc::bytes32 read_storage(lmdb::Transaction& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<uint64_t> block_num) {
    std::optional<ByteView> val{};
    if (block_num) {
        val = historical_storage(txn, address, incarnation, location, *block_num);
    }
    if (!val) {
        auto table{txn.open(table::kPlainState)};
        val = table->get(storage_prefix(address, incarnation), full_view(location));
    }
    if (!val) {
        return {};
    }

    evmc::bytes32 res{};
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

static std::optional<uint64_t> historical_previous_incarnation() {
    // TODO(Andrew): implement properly
    return std::nullopt;
}

std::optional<uint64_t> read_previous_incarnation(lmdb::Transaction& txn, const evmc::address& address,
                                                  std::optional<uint64_t> block_num) {
    if (block_num) {
        return historical_previous_incarnation();
    }

    auto incarnation_table{txn.open(table::kIncarnationMap)};
    std::optional<ByteView> val{incarnation_table->get(full_view(address))};
    if (!val) {
        return std::nullopt;
    }
    assert(val->length() == 8);
    return boost::endian::load_big_u64(val->data());
}

AccountChanges read_account_changes(lmdb::Transaction& txn, uint64_t block_num) {
    AccountChanges changes;
    auto table{txn.open(table::kPlainAccountChangeSet)};
    Bytes blck_key{block_key(block_num)};
    MDB_val key_mdb{to_mdb_val(blck_key)};
    MDB_val data_mdb;
    for (int rc{table->seek_exact(&key_mdb, &data_mdb)}; rc != MDB_NOTFOUND;
         rc = table->get_next_dup(&key_mdb, &data_mdb)) {
        lmdb::err_handler(rc);
        ByteView data{from_mdb_val(data_mdb)};
        assert(data.length() >= kAddressLength);
        evmc::address address;
        std::memcpy(address.bytes, data.data(), kAddressLength);
        data.remove_prefix(kAddressLength);
        changes[address] = data;
    }
    return changes;
}

StorageChanges read_storage_changes(lmdb::Transaction& txn, uint64_t block_num) {
    StorageChanges changes;
    auto table{txn.open(table::kPlainStorageChangeSet)};
    const Bytes prefix{block_key(block_num)};
    MDB_val key_mdb{to_mdb_val(prefix)};
    MDB_val data_mdb;
    for (int rc{table->seek(&key_mdb, &data_mdb)}; rc != MDB_NOTFOUND; rc = table->get_next(&key_mdb, &data_mdb)) {
        lmdb::err_handler(rc);

        ByteView key{from_mdb_val(key_mdb)};
        if (!has_prefix(key, prefix)) {
            break;
        }
        key.remove_prefix(prefix.length());
        assert(key.length() == kStoragePrefixLength);
        evmc::address address;
        std::memcpy(address.bytes, key.data(), kAddressLength);
        key.remove_prefix(kAddressLength);
        uint64_t incarnation{boost::endian::load_big_u64(key.data())};

        ByteView data{from_mdb_val(data_mdb)};
        assert(data.length() >= kHashLength);
        evmc::bytes32 location;
        std::memcpy(location.bytes, data.data(), kHashLength);
        data.remove_prefix(kHashLength);

        changes[address][incarnation][location] = data;
    }
    return changes;
}

bool read_storage_mode_receipts(lmdb::Transaction& txn) {
    auto table{txn.open(table::kDatabaseInfo)};
    std::optional<ByteView> val{table->get(byte_view_of_c_str(kStorageModeReceipts))};
    return val && val->length() == 1 && (*val)[0] == 1;
}

bool migration_happened(lmdb::Transaction& txn, const char* name) {
    auto tbl{txn.open(table::kMigrations)};
    return tbl->get(byte_view_of_c_str(name)).has_value();
}

std::optional<ChainConfig> read_chain_config(lmdb::Transaction& txn) {
    auto headers_key{block_key(0)};
    auto mdb_key{to_mdb_val(headers_key)};
    auto genesis_hash{txn.get(db::table::kCanonicalHashes, &mdb_key)};
    if (!genesis_hash.has_value()) {
        return std::nullopt;
    }

    mdb_key = to_mdb_val(*genesis_hash);
    auto config_value = txn.get(table::kConfig, &mdb_key);
    if (!config_value) {
        return std::nullopt;
    }

    return parse_chain_config(byte_ptr_cast(config_value->c_str()));
}

static inline void read_json_config_member(const nlohmann::json& json, const std::string& key,
                                           std::optional<uint64_t>& target) {
    if (json.contains(key) && json[key].is_number()) {
        target.emplace(json[key].get<uint64_t>());
    }
}

/*
* Sample config
{
"byzantiumBlock":4370000,
"chainId":1,
"constantinopleBlock":7280000,
"daoForkBlock":1920000,
"daoForkSupport":true,
"eip150Block":2463000,
"eip150Hash":"0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
"eip155Block":2675000,
"eip158Block":2675000,
"ethash":{},
"homesteadBlock":1150000,
"istanbulBlock":9069000,
"muirGlacierBlock":9200000,
"petersburgBlock":7280000
}
*/
std::optional<ChainConfig> parse_chain_config(std::string_view json) {
    // https://github.com/nlohmann/json/issues/2204
    auto config_json = nlohmann::json::parse(json, nullptr, false);

    if (config_json == nlohmann::json::value_t::discarded || !config_json.contains("chainId") ||
        !config_json["chainId"].is_number()) {
        return std::nullopt;
    }

    ChainConfig config{};
    config.chain_id = config_json["chainId"].get<uint64_t>();

    read_json_config_member(config_json, "homesteadBlock", config.homestead_block);
    read_json_config_member(config_json, "eip150Block", config.tangerine_whistle_block);

    /** Quote @yperbasis
    * "We can treat both eip155 & eip158 as synonyms for Spurious Dragon."
    */
    read_json_config_member(config_json, "eip155Block", config.spurious_dragon_block);
    read_json_config_member(config_json, "eip158Block", config.spurious_dragon_block);


    read_json_config_member(config_json, "byzantiumBlock", config.byzantium_block);
    read_json_config_member(config_json, "constantinopleBlock", config.constantinople_block);
    read_json_config_member(config_json, "petersburgBlock", config.petersburg_block);
    read_json_config_member(config_json, "istanbulBlock", config.istanbul_block);
    read_json_config_member(config_json, "muirGlacierBlock", config.muir_glacier_block);
    read_json_config_member(config_json, "daoForkBlock", config.dao_block);
    read_json_config_member(config_json, "berlinBlock", config.berlin_block);

    return config;
}

}  // namespace silkworm::db
