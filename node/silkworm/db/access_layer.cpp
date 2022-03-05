/*
   Copyright 2020-2022 The Silkworm Authors

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

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>

#include "bitmap.hpp"
#include "tables.hpp"

namespace silkworm::db {

std::optional<VersionBase> read_schema_version(mdbx::txn& txn) {
    Cursor src(txn, db::table::kDatabaseInfo);
    if (!src.seek(mdbx::slice{kDbSchemaVersionKey})) {
        return std::nullopt;
    }

    auto data{src.current()};
    SILKWORM_ASSERT(data.value.length() == 12);
    auto Major{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Minor{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Patch{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    return VersionBase{Major, Minor, Patch};
}

void write_schema_version(mdbx::txn& txn, const VersionBase& schema_version) {
    auto old_schema_version{read_schema_version(txn)};
    if (old_schema_version.has_value()) {
        if (schema_version == old_schema_version.value()) {
            // Simply return. No changes
            return;
        }
        if (schema_version < old_schema_version.value()) {
            throw std::runtime_error("Cannot downgrade schema version");
        }
    }
    Bytes value(12, '\0');
    endian::store_big_u32(&value[0], schema_version.Major);
    endian::store_big_u32(&value[4], schema_version.Minor);
    endian::store_big_u32(&value[8], schema_version.Patch);

    Cursor src(txn, db::table::kDatabaseInfo);
    src.upsert(mdbx::slice{kDbSchemaVersionKey}, to_slice(value));
}

std::optional<BlockHeader> read_header(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_header(txn, key);
}

std::optional<BlockHeader> read_header(mdbx::txn& txn, ByteView key) {
    auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return std::nullopt;
    }
    BlockHeader header;
    ByteView encoded_header{raw_header.data(), raw_header.length()};
    rlp::success_or_throw(rlp::decode(encoded_header, header));
    return header;
}

Bytes read_header_raw(mdbx::txn& txn, ByteView key) {
    Cursor src(txn, db::table::kHeaders);
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return {};
    }
    return Bytes{from_slice(data.value)};
}

void write_header(mdbx::txn& txn, const BlockHeader& header, bool with_header_numbers) {
    Bytes value{};
    rlp::encode(value, header);
    auto header_hash{header.hash()};
    auto key{db::block_key(header.number, header_hash.bytes)};

    Cursor target(txn, table::kHeaders);
    target.upsert(to_slice(key), to_slice(value));
    if (with_header_numbers) {
        write_header_number(txn, header_hash.bytes, header.number);
    }
}

void write_header_number(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    Cursor target(txn, table::kHeaderNumbers);
    auto value{db::block_key(number)};
    target.upsert({hash, kHashLength}, to_slice(value));
}

std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, BlockNum block_number,
                                                   const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_total_difficulty(txn, key);
}

std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, ByteView key) {
    Cursor src(txn, table::kDifficulty);
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    intx::uint256 td{0};
    ByteView data_view{from_slice(data.value)};
    rlp::success_or_throw(rlp::decode(data_view, td));
    return td;
}

void write_total_difficulty(mdbx::txn& txn, const Bytes& key, const intx::uint256& total_difficulty) {
    SILKWORM_ASSERT(key.length() == sizeof(BlockNum) + kHashLength);
    Bytes value{};
    rlp::encode(value, total_difficulty);

    Cursor target(txn, table::kDifficulty);
    target.upsert(to_slice(key), to_slice(value));
}

void write_total_difficulty(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                            intx::uint256& total_difficulty) {
    auto key{block_key(block_number, hash)};
    write_total_difficulty(txn, key, total_difficulty);
}

void write_canonical_header(mdbx::txn& txn, const BlockHeader& header) {
    write_canonical_header_hash(txn, header.hash().bytes, header.number);
}

void write_canonical_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], BlockNum number) {
    Cursor target(txn, table::kCanonicalHashes);
    auto key{db::block_key(number)};
    target.upsert(to_slice(key), db::to_slice(hash));
}

void read_transactions(mdbx::txn& txn, uint64_t base_id, uint64_t count, std::vector<Transaction>& out) {
    if (count == 0) {
        out.clear();
        return;
    }
    Cursor src(txn, table::kBlockTransactions);
    read_transactions(src, base_id, count, out);
}

void write_transactions(mdbx::txn& txn, const std::vector<Transaction>& transactions, uint64_t base_id) {
    if (transactions.empty()) {
        return;
    }

    Cursor target(txn, table::kBlockTransactions);
    auto key{db::block_key(base_id)};
    for (const auto& transaction : transactions) {
        Bytes value{};
        rlp::encode(value, transaction);
        mdbx::slice value_slice{value.data(), value.length()};
        target.put(to_slice(key), &value_slice, MDBX_APPEND);
        ++base_id;
        endian::store_big_u64(key.data(), base_id);
    }
}

void read_transactions(mdbx::cursor& txn_table, uint64_t base_id, uint64_t count, std::vector<Transaction>& v) {
    v.resize(count);
    if (count == 0) {
        return;
    }

    auto key{db::block_key(base_id)};

    uint64_t i{0};
    for (auto data{txn_table.find(to_slice(key), false)}; data.done && i < count;
         data = txn_table.to_next(/*throw_notfound = */ false), ++i) {
        ByteView data_view{from_slice(data.value)};
        rlp::success_or_throw(rlp::decode(data_view, v.at(i)));
    }
    SILKWORM_ASSERT(i == count);
}

bool read_block(mdbx::txn& txn, BlockNum block_number, bool read_senders, BlockWithHash& bh) {
    // Locate canonical hash

    Cursor canonical_hashes_cursor(txn, table::kCanonicalHashes);
    auto key{block_key(block_number)};
    auto data{canonical_hashes_cursor.find(to_slice(key), false)};
    if (!data) {
        return false;
    }

    SILKWORM_ASSERT(data.value.length() == kHashLength);
    std::memcpy(bh.hash.bytes, data.value.data(), kHashLength);

    // Read header
    key = block_key(block_number, bh.hash.bytes);
    auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    rlp::success_or_throw(rlp::decode(raw_header_view, bh.block.header));

    return read_body(txn, key, read_senders, bh.block);
}

bool read_body(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength], bool read_senders,
               BlockBody& out) {
    auto key{block_key(block_number, hash)};
    return read_body(txn, key, read_senders, out);
}

bool read_body(mdbx::txn& txn, const Bytes& key, bool read_senders, BlockBody& out) {
    Cursor src(txn, table::kBlockBodies);
    auto data{src.find(to_slice(key), false)};
    if (!data) {
        return false;
    }
    ByteView data_view{from_slice(data.value)};
    auto body{detail::decode_stored_block_body(data_view)};

    std::swap(out.ommers, body.ommers);
    read_transactions(txn, body.base_txn_id, body.txn_count, out.transactions);
    if (!out.transactions.empty() && read_senders) {
        parse_senders(txn, key, out.transactions);
    }
    return true;
}

void write_body(mdbx::txn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    detail::BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.txn_count = body.transactions.size();
    body_for_storage.base_txn_id =
        increment_map_sequence(txn, table::kBlockTransactions.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{db::block_key(number, hash)};

    Cursor target(txn, table::kBlockBodies);
    target.upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id);
}

static ByteView read_senders_raw(mdbx::txn& txn, const Bytes& key) {
    Cursor src(txn, table::kSenders);
    auto data{src.find(to_slice(key), /*throw_notfound = */ false)};
    return data ? from_slice(data.value) : ByteView();
}

std::vector<evmc::address> read_senders(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_senders(txn, key);
}

std::vector<evmc::address> read_senders(mdbx::txn& txn, const Bytes& key) {
    std::vector<evmc::address> senders{};
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.length() % kAddressLength == 0);
        senders.resize(data_view.length() / kAddressLength);
        std::memcpy(senders.data(), data_view.data(), data_view.length());
    }
    return senders;
}

void parse_senders(mdbx::txn& txn, const Bytes& key, std::vector<Transaction>& out) {
    if (out.empty()) {
        return;
    }
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.length() % kAddressLength == 0);
        SILKWORM_ASSERT(data_view.length() / kAddressLength == out.size());
        auto addresses = reinterpret_cast<const evmc::address*>(data_view.data());
        size_t idx{0};
        for (auto& transaction : out) {
            transaction.from.emplace(addresses[idx++]);
        }
    } else {
        // Might be empty due to pruning
        for (auto& transaction : out) {
            transaction.recover_sender();
        }
    }
}

std::optional<ByteView> read_code(mdbx::txn& txn, const evmc::bytes32& code_hash) {
    Cursor src(txn, table::kCode);
    auto key{to_slice(code_hash)};
    auto data{src.find(key, /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    return from_slice(data.value);
}

// Erigon FindByHistory for account
static std::optional<ByteView> historical_account(mdbx::txn& txn, const evmc::address& address, BlockNum block_number) {
    Cursor src(txn, table::kAccountHistory);
    const Bytes history_key{account_history_key(address, block_number)};
    const auto data{src.lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data || !data.key.starts_with(to_slice(address))) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::read(from_slice(data.value))};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    src.bind(txn, table::kAccountChangeSet);
    const Bytes change_set_key{block_key(*change_block)};
    return find_value_suffix(src, change_set_key, address);
}

// Erigon FindByHistory for storage
static std::optional<ByteView> historical_storage(mdbx::txn& txn, const evmc::address& address, uint64_t incarnation,
                                                  const evmc::bytes32& location, BlockNum block_number) {
    Cursor src(txn, table::kStorageHistory);
    const Bytes history_key{storage_history_key(address, location, block_number)};
    const auto data{src.lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }

    const ByteView k{from_slice(data.key)};
    SILKWORM_ASSERT(k.length() == kAddressLength + kHashLength + sizeof(BlockNum));

    if (k.substr(0, kAddressLength) != ByteView{address} ||
        k.substr(kAddressLength, kHashLength) != ByteView{location}) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::read(from_slice(data.value))};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    src.bind(txn, table::kStorageChangeSet);
    const Bytes change_set_key{storage_change_key(*change_block, address, incarnation)};
    return find_value_suffix(src, change_set_key, location);
}

std::optional<Account> read_account(mdbx::txn& txn, const evmc::address& address, std::optional<BlockNum> block_num) {
    std::optional<ByteView> encoded{block_num.has_value() ? historical_account(txn, address, block_num.value())
                                                          : std::nullopt};

    if (!encoded.has_value()) {
        Cursor src(txn, table::kPlainState);
        if (auto data{src.find({address.bytes, sizeof(evmc::address)}, false)}; data.done) {
            encoded.emplace(from_slice(data.value));
        }
    }
    if (!encoded.has_value() || encoded->empty()) {
        return std::nullopt;
    }

    auto [acc, err]{Account::from_encoded_storage(encoded.value())};
    rlp::success_or_throw(err);

    if (acc.incarnation > 0 && acc.code_hash == kEmptyHash) {
        // restore code hash
        Cursor src(txn, table::kPlainCodeHash);
        auto key{storage_prefix(address, acc.incarnation)};
        if (auto data{src.find(to_slice(key), /*throw_notfound*/ false)};
            data.done && data.value.length() == kHashLength) {
            std::memcpy(acc.code_hash.bytes, data.value.data(), kHashLength);
        }
    }

    return acc;
}

evmc::bytes32 read_storage(mdbx::txn& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<BlockNum> block_num) {
    std::optional<ByteView> val{block_num.has_value()
                                    ? historical_storage(txn, address, incarnation, location, block_num.value())
                                    : std::nullopt};
    if (!val.has_value()) {
        Cursor src(txn, table::kPlainState);
        auto key{storage_prefix(address, incarnation)};
        val = find_value_suffix(src, key, location);
    }

    if (!val.has_value()) {
        return {};
    }

    evmc::bytes32 res{};
    SILKWORM_ASSERT(val->length() <= kHashLength);
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

static std::optional<uint64_t> historical_previous_incarnation() {
    // TODO (Andrew) implement properly
    return std::nullopt;
}

std::optional<uint64_t> read_previous_incarnation(mdbx::txn& txn, const evmc::address& address,
                                                  std::optional<BlockNum> block_num) {
    if (block_num.has_value()) {
        return historical_previous_incarnation();
    }

    Cursor src(txn, table::kIncarnationMap);
    if (auto data{src.find(to_slice(address), /*throw_notfound=*/false)}; data.done) {
        SILKWORM_ASSERT(data.value.length() == 8);
        return endian::load_big_u64(static_cast<uint8_t*>(data.value.data()));
    }
    return std::nullopt;
}

AccountChanges read_account_changes(mdbx::txn& txn, BlockNum block_num) {
    AccountChanges changes;

    Cursor src(txn, table::kAccountChangeSet);
    auto key{block_key(block_num)};
    auto data{src.find(to_slice(key), /*throw_notfound=*/false)};
    while (data) {
        SILKWORM_ASSERT(data.value.length() >= kAddressLength);
        evmc::address address;
        std::memcpy(address.bytes, data.value.data(), kAddressLength);
        data.value.remove_prefix(kAddressLength);
        changes[address] = db::from_slice(data.value);
        data = src.to_current_next_multi(/*throw_notfound=*/false);
    }

    return changes;
}

StorageChanges read_storage_changes(mdbx::txn& txn, BlockNum block_num) {
    StorageChanges changes;

    const Bytes block_prefix{block_key(block_num)};

    Cursor src(txn, table::kStorageChangeSet);
    auto key_prefix{to_slice(block_prefix)};
    auto data{src.lower_bound(key_prefix, false)};
    while (data) {
        if (!data.key.starts_with(key_prefix)) {
            break;
        }

        data.key.remove_prefix(key_prefix.length());
        SILKWORM_ASSERT(data.key.length() == kPlainStoragePrefixLength);

        evmc::address address;
        std::memcpy(address.bytes, data.key.data(), kAddressLength);
        data.key.remove_prefix(kAddressLength);
        uint64_t incarnation{endian::load_big_u64(static_cast<uint8_t*>(data.key.data()))};

        SILKWORM_ASSERT(data.value.length() >= kHashLength);
        evmc::bytes32 location;
        std::memcpy(location.bytes, data.value.data(), kHashLength);
        data.value.remove_prefix(kHashLength);

        changes[address][incarnation][location] = db::from_slice(data.value);
        data = src.to_next(/*throw_notfound=*/false);
    }

    return changes;
}

std::optional<ChainConfig> read_chain_config(mdbx::txn& txn) {
    Cursor src(txn, table::kCanonicalHashes);
    auto data{src.find(to_slice(block_key(0)), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    const auto key{data.value};

    src.bind(txn, table::kConfig);
    data = src.find(key, /*throw_notfound=*/false);
    if (!data) {
        return std::nullopt;
    }

    // https://github.com/nlohmann/json/issues/2204
    const auto json = nlohmann::json::parse(data.value.as_string(), nullptr, false);
    return ChainConfig::from_json(json);
}

void write_head_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength]) {
    Cursor target(txn, table::kHeadHeader);
    mdbx::slice key(db::table::kLastHeaderKey);
    target.upsert(key, to_slice(hash));
}

std::optional<evmc::bytes32> read_head_header_hash(mdbx::txn& txn) {
    Cursor src(txn, table::kHeadHeader);
    mdbx::slice key(db::table::kLastHeaderKey);
    auto data{src.find(key, /*throw_notfound=*/false)};
    if (!data || data.value.length() != sizeof(evmc::bytes32)) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

uint64_t increment_map_sequence(mdbx::txn& txn, const char* map_name, uint64_t increment) {
    uint64_t current_value{read_map_sequence(txn, map_name)};
    if (increment) {
        Cursor target(txn, table::kSequence);
        mdbx::slice key(map_name);
        uint64_t new_value{current_value + increment};  // Note ! May overflow
        Bytes new_data(sizeof(uint64_t), '\0');
        endian::store_big_u64(new_data.data(), new_value);
        target.upsert(key, to_slice(new_data));
    }
    return current_value;
}

uint64_t read_map_sequence(mdbx::txn& txn, const char* map_name) {
    Cursor target(txn, table::kSequence);
    mdbx::slice key(map_name);
    auto data{target.find(key, /*throw_notfound=*/false)};
    if (!data.done) {
        return 0;
    }
    if (data.value.length() != sizeof(uint64_t)) {
        throw std::length_error("Bad sequence value in db");
    }
    return endian::load_big_u64(from_slice(data.value).data());
}

}  // namespace silkworm::db
