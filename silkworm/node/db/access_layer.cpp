/*
   Copyright 2022 The Silkworm Authors

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

#include <bit>
#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/types/receipt_cbor.hpp>

namespace silkworm::db {

std::optional<VersionBase> read_schema_version(ROTxn& txn) {
    auto cursor = txn.ro_cursor(db::table::kDatabaseInfo);
    if (!cursor->seek(mdbx::slice{kDbSchemaVersionKey})) {
        return std::nullopt;
    }

    auto data{cursor->current()};
    SILKWORM_ASSERT(data.value.length() == 12);
    auto Major{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Minor{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    data.value.remove_prefix(sizeof(uint32_t));
    auto Patch{endian::load_big_u32(static_cast<uint8_t*>(data.value.data()))};
    return VersionBase{Major, Minor, Patch};
}

void write_schema_version(RWTxn& txn, const VersionBase& schema_version) {
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

    PooledCursor src(txn, db::table::kDatabaseInfo);
    src.upsert(mdbx::slice{kDbSchemaVersionKey}, to_slice(value));
}

void write_build_info_height(RWTxn& txn, const Bytes& key, BlockNum height) {
    auto cursor = txn.rw_cursor(db::table::kDatabaseInfo);
    Bytes value{db::block_key(height)};
    cursor->upsert(db::to_slice(key), db::to_slice(value));
}

std::vector<std::string> read_snapshots(ROTxn& txn) {
    auto db_info_cursor = txn.ro_cursor(table::kDatabaseInfo);
    if (!db_info_cursor->seek(mdbx::slice{kDbSnapshotsKey})) {
        return {};
    }
    const auto data{db_info_cursor->current()};
    // https://github.com/nlohmann/json/issues/2204
    const auto json = nlohmann::json::parse(data.value.as_string(), nullptr, /*.allow_exceptions=*/false);
    return json.get<std::vector<std::string>>();
}

void write_snapshots(RWTxn& txn, const std::vector<std::string>& snapshot_file_names) {
    auto db_info_cursor = txn.rw_cursor(table::kDatabaseInfo);
    nlohmann::json json_value = snapshot_file_names;
    db_info_cursor->upsert(mdbx::slice{kDbSnapshotsKey}, mdbx::slice(json_value.dump().data()));
}

std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_number, const evmc::bytes32& hash) {
    return read_header(txn, block_number, hash.bytes);
}

std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_header(txn, key);
}

std::optional<BlockHeader> read_header(ROTxn& txn, ByteView key) {
    auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return std::nullopt;
    }
    BlockHeader header;
    ByteView encoded_header{raw_header.data(), raw_header.length()};
    success_or_throw(rlp::decode(encoded_header, header));
    return header;
}

Bytes read_header_raw(ROTxn& txn, ByteView key) {
    auto cursor = txn.ro_cursor(db::table::kHeaders);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return {};
    }
    return Bytes{from_slice(data.value)};
}

std::optional<BlockHeader> read_header(ROTxn& txn, const evmc::bytes32& hash) {
    auto block_num = read_block_number(txn, hash);
    if (!block_num) {
        return std::nullopt;
    }
    return read_header(txn, *block_num, hash.bytes);
}

bool read_header(ROTxn& txn, const evmc::bytes32& hash, BlockNum number, BlockHeader& header) {
    const Bytes key{block_key(number, hash.bytes)};
    const auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    success_or_throw(rlp::decode(raw_header_view, header));
    return true;
}

std::vector<BlockHeader> read_headers(ROTxn& txn, BlockNum height) {
    std::vector<BlockHeader> headers;
    process_headers_at_height(txn, height, [&](BlockHeader&& header) {
        headers.emplace_back(std::move(header));
    });
    return headers;
}

// process headers at specific height
size_t process_headers_at_height(ROTxn& txn, BlockNum height, std::function<void(BlockHeader&&)> process_func) {
    auto headers_cursor = txn.ro_cursor(db::table::kHeaders);
    auto key_prefix{db::block_key(height)};

    auto count = db::cursor_for_prefix(
        *headers_cursor, key_prefix,
        [&process_func]([[maybe_unused]] ByteView key, ByteView raw_header) {
            if (raw_header.empty()) throw std::logic_error("empty header in table Headers");
            BlockHeader header;
            ByteView encoded_header{raw_header.data(), raw_header.length()};
            success_or_throw(rlp::decode(encoded_header, header));
            process_func(std::move(header));
        },
        db::CursorMoveDirection::Forward);

    return count;
}

void write_header(RWTxn& txn, const BlockHeader& header, bool with_header_numbers) {
    write_header_ex(txn, header, with_header_numbers);
}

evmc::bytes32 write_header_ex(RWTxn& txn, const BlockHeader& header, bool with_header_numbers) {
    Bytes value{};
    rlp::encode(value, header);
    auto header_hash = std::bit_cast<evmc_bytes32>(keccak256(value));  // avoid header.hash() because it re-does rlp encoding
    auto key{db::block_key(header.number, header_hash.bytes)};
    auto skey = db::to_slice(key);
    auto svalue = db::to_slice(value);

    auto target = txn.rw_cursor(table::kHeaders);
    target->upsert(skey, svalue);
    if (with_header_numbers) {
        write_header_number(txn, header_hash.bytes, header.number);
    }
    return header_hash;
}

std::optional<ByteView> read_rlp_encoded_header(ROTxn& txn, BlockNum bn, const evmc::bytes32& hash) {
    auto header_cursor = txn.ro_cursor(db::table::kHeaders);
    auto key = db::block_key(bn, hash.bytes);
    auto data = header_cursor->find(db::to_slice(key), /*throw_notfound*/ false);
    if (!data) return std::nullopt;
    return db::from_slice(data.value);
}

std::optional<BlockHeader> read_canonical_header(ROTxn& txn, BlockNum b) {  // also known as read-header-by-number
    std::optional<evmc::bytes32> h = read_canonical_hash(txn, b);
    if (!h) {
        return std::nullopt;  // not found
    }
    return read_header(txn, b, h->bytes);
}

static Bytes header_numbers_key(evmc::bytes32 hash) {
    return {hash.bytes, 32};
}

std::optional<BlockNum> read_block_number(ROTxn& txn, const evmc::bytes32& hash) {
    auto blockhashes_cursor = txn.ro_cursor(db::table::kHeaderNumbers);
    auto key = header_numbers_key(hash);
    auto data = blockhashes_cursor->find(db::to_slice(key), /*throw_notfound*/ false);
    if (!data) {
        return std::nullopt;
    }
    auto block_num = endian::load_big_u64(static_cast<const unsigned char*>(data.value.data()));
    return block_num;
}

void write_header_number(RWTxn& txn, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    auto target = txn.rw_cursor(table::kHeaderNumbers);
    auto value{db::block_key(number)};
    target->upsert({hash, kHashLength}, to_slice(value));
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum b, const evmc::bytes32& hash) {
    return db::read_total_difficulty(txn, b, hash.bytes);
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum block_number,
                                                   const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_total_difficulty(txn, key);
}

std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, ByteView key) {
    auto cursor = txn.ro_cursor(table::kDifficulty);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return std::nullopt;
    }
    intx::uint256 td{0};
    ByteView data_view{from_slice(data.value)};
    success_or_throw(rlp::decode(data_view, td));
    return td;
}

void write_total_difficulty(RWTxn& txn, const Bytes& key, const intx::uint256& total_difficulty) {
    SILKWORM_ASSERT(key.length() == sizeof(BlockNum) + kHashLength);
    Bytes value{};
    rlp::encode(value, total_difficulty);

    auto target = txn.rw_cursor(table::kDifficulty);
    target->upsert(to_slice(key), to_slice(value));
}

void write_total_difficulty(RWTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                            const intx::uint256& total_difficulty) {
    auto key{block_key(block_number, hash)};
    write_total_difficulty(txn, key, total_difficulty);
}

void write_total_difficulty(RWTxn& txn, BlockNum block_number, const evmc::bytes32& hash,
                            const intx::uint256& total_difficulty) {
    auto key{block_key(block_number, hash.bytes)};
    write_total_difficulty(txn, key, total_difficulty);
}

std::tuple<BlockNum, evmc::bytes32> read_canonical_head(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto data = cursor->to_last();
    if (!data) return {};
    evmc::bytes32 hash{};
    std::memcpy(hash.bytes, data.value.data(), kHashLength);
    BlockNum bn = endian::load_big_u64(static_cast<const unsigned char*>(data.key.data()));
    return {bn, hash};
}

std::optional<evmc::bytes32> read_canonical_header_hash(ROTxn& txn, BlockNum number) {
    auto cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto key{db::block_key(number)};
    auto data{cursor->find(to_slice(key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    evmc::bytes32 ret{};
    std::memcpy(ret.bytes, data.value.data(), kHashLength);
    return ret;
}

void write_canonical_header(RWTxn& txn, const BlockHeader& header) {
    write_canonical_header_hash(txn, header.hash().bytes, header.number);
}

void write_canonical_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength], BlockNum number) {
    auto cursor = txn.rw_cursor(table::kCanonicalHashes);
    auto key{db::block_key(number)};
    cursor->upsert(to_slice(key), db::to_slice(hash));
}

void read_transactions(ROTxn& txn, uint64_t base_id, uint64_t count, std::vector<Transaction>& out) {
    if (count == 0) {
        out.clear();
        return;
    }
    auto cursor = txn.ro_cursor(table::kBlockTransactions);
    read_transactions(*cursor, base_id, count, out);
}

void write_transactions(RWTxn& txn, const std::vector<Transaction>& transactions, uint64_t base_id) {
    if (transactions.empty()) {
        return;
    }

    auto cursor = txn.rw_cursor(table::kBlockTransactions);
    auto key{db::block_key(base_id)};
    for (const auto& transaction : transactions) {
        Bytes value{};
        rlp::encode(value, transaction);
        mdbx::slice value_slice{value.data(), value.length()};
        cursor->put(to_slice(key), &value_slice, MDBX_APPEND);
        ++base_id;
        endian::store_big_u64(key.data(), base_id);
    }
}

void read_transactions(ROCursor& txn_table, uint64_t base_id, uint64_t count, std::vector<Transaction>& out) {
    out.resize(count);
    if (count == 0) {
        return;
    }

    auto key{db::block_key(base_id)};

    uint64_t i{0};
    for (auto data{txn_table.find(to_slice(key), false)}; data.done && i < count;
         data = txn_table.to_next(/*throw_notfound = */ false), ++i) {
        ByteView data_view{from_slice(data.value)};
        success_or_throw(rlp::decode(data_view, out.at(i)));
    }
    SILKWORM_ASSERT(i == count);
}

static void read_rlp_transactions(ROTxn& txn, uint64_t base_id, uint64_t count, std::vector<Bytes>& rlp_txs) {
    rlp_txs.resize(count);
    if (count == 0) {
        return;
    }

    const auto key{db::block_key(base_id)};
    auto cursor = txn.ro_cursor(table::kBlockTransactions);
    uint64_t i{0};
    for (auto data{cursor->find(to_slice(key), false)}; data.done && i < count;
         data = cursor->to_next(/*throw_notfound = */ false), ++i) {
        rlp_txs[i] = from_slice(data.value);
    }
    SILKWORM_ASSERT(i == count);
}

bool read_block_by_number(ROTxn& txn, BlockNum number, bool read_senders, Block& block) {
    auto canonical_hashes_cursor = txn.ro_cursor(table::kCanonicalHashes);
    const Bytes key{block_key(number)};
    const auto data{canonical_hashes_cursor->find(to_slice(key), false)};
    if (!data) {
        return false;
    }
    SILKWORM_ASSERT(data.value.length() == kHashLength);
    const auto hash_ptr{static_cast<const uint8_t*>(data.value.data())};
    return read_block(txn, std::span<const uint8_t, kHashLength>{hash_ptr, kHashLength}, number, read_senders, block);
}

bool read_block(ROTxn& txn, const evmc::bytes32& hash, BlockNum number, Block& block) {
    // Read header
    read_header(txn, hash, number, block.header);
    // Read body
    return read_body(txn, hash, number, block);  // read_senders == false
}

bool read_block(ROTxn& txn, std::span<const uint8_t, kHashLength> hash, BlockNum number, bool read_senders,
                Block& block) {
    // Read header
    const Bytes key{block_key(number, hash)};
    const auto raw_header{read_header_raw(txn, key)};
    if (raw_header.empty()) {
        return false;
    }
    ByteView raw_header_view(raw_header);
    success_or_throw(rlp::decode(raw_header_view, block.header));

    return read_body(txn, key, read_senders, block);
}

// process blocks at specific height
size_t process_blocks_at_height(ROTxn& txn, BlockNum height, std::function<void(Block&)> process_func, bool read_senders) {
    auto bodies_cursor = txn.ro_cursor(db::table::kBlockBodies);
    auto key_prefix{db::block_key(height)};

    auto count = db::cursor_for_prefix(
        *bodies_cursor, key_prefix,
        [&process_func, &txn, &height, &read_senders](ByteView key, ByteView raw_body) {
            if (raw_body.empty()) throw std::logic_error("empty header in table Headers");
            // read block...
            Block block;
            // ...ommers
            auto body = detail::decode_stored_block_body(raw_body);
            std::swap(block.ommers, body.ommers);
            // ...transactions
            ensure(body.txn_count > 1, "unexpected txn_count=" + std::to_string(body.txn_count) + " for number=" + std::to_string(height));
            read_transactions(txn, body.base_txn_id + 1, body.txn_count - 2, block.transactions);
            // ...senders
            if (!block.transactions.empty() && read_senders) {
                Bytes key_bytes{key.data(), key.length()};  // TODO(canepat) avoid unnecessary copy by changing read_senders API
                db::parse_senders(txn, key_bytes, block.transactions);
            }
            // ...header
            auto [block_num, hash] = split_block_key(key);
            const bool present = read_header(txn, hash, block_num, block.header);
            ensure(present, "header not found for body number= " + std::to_string(block_num) + ", hash= " + silkworm::to_hex(hash));
            // invoke handler
            process_func(block);
        },
        db::CursorMoveDirection::Forward);

    return count;
}

bool read_body(ROTxn& txn, const evmc::bytes32& h, BlockNum bn, BlockBody& body) {
    return db::read_body(txn, bn, h.bytes, /*read_senders=*/false, body);
}

bool read_body(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength], bool read_senders,
               BlockBody& out) {
    auto key{block_key(block_number, hash)};
    return read_body(txn, key, read_senders, out);
}

bool read_body(ROTxn& txn, const Bytes& key, bool read_senders, BlockBody& out) {
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    auto data{cursor->find(to_slice(key), false)};
    if (!data) {
        return false;
    }
    ByteView data_view{from_slice(data.value)};
    auto body{detail::decode_stored_block_body(data_view)};

    std::swap(out.ommers, body.ommers);
    std::swap(out.withdrawals, body.withdrawals);
    ensure(body.txn_count > 1, "unexpected txn_count=" + std::to_string(body.txn_count) + " for key=" + to_hex(key));
    read_transactions(txn, body.base_txn_id + 1, body.txn_count - 2, out.transactions);
    if (!out.transactions.empty() && read_senders) {
        parse_senders(txn, key, out.transactions);
    }
    return true;
}

bool read_rlp_transactions(ROTxn& txn, BlockNum height, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) {
    const auto key{block_key(height, hash.bytes)};
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    const auto data{cursor->find(to_slice(key), false)};
    if (!data) return false;

    ByteView data_view{from_slice(data.value)};
    const auto body{detail::decode_stored_block_body(data_view)};
    ensure(body.txn_count > 1, "unexpected txn_count=" + std::to_string(body.txn_count) + " for key=" + std::to_string(height));
    read_rlp_transactions(txn, body.base_txn_id + 1, body.txn_count - 2, rlp_txs);

    return true;
}

bool read_body(ROTxn& txn, const evmc::bytes32& h, BlockBody& body) {
    auto block_num = read_block_number(txn, h);
    if (!block_num) {
        return false;
    }
    return db::read_body(txn, *block_num, h.bytes, /*read_senders=*/false, body);
}

bool read_canonical_block(ROTxn& txn, BlockNum height, Block& block) {
    std::optional<evmc::bytes32> h = read_canonical_hash(txn, height);
    if (!h) return false;

    bool present = read_header(txn, *h, height, block.header);
    if (!present) return false;

    return read_body(txn, *h, height, block);
}

bool has_body(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    auto cursor = txn.ro_cursor(table::kBlockBodies);
    return cursor->find(to_slice(key), false);
}

bool has_body(ROTxn& txn, BlockNum block_number, const evmc::bytes32& hash) {
    return db::has_body(txn, block_number, hash.bytes);
}

void write_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum bn) {
    write_body(txn, body, hash.bytes, bn);
}

void write_body(RWTxn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], const BlockNum number) {
    detail::BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.withdrawals = body.withdrawals;
    body_for_storage.txn_count = body.transactions.size() + 2;
    body_for_storage.base_txn_id =
        increment_map_sequence(txn, table::kBlockTransactions.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{db::block_key(number, hash)};

    auto target = txn.rw_cursor(table::kBlockBodies);
    target->upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id + 1);
}

void write_raw_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum bn) {
    detail::BlockBodyForStorage body_for_storage{};
    body_for_storage.ommers = body.ommers;
    body_for_storage.withdrawals = body.withdrawals;
    body_for_storage.txn_count = body.transactions.size();
    body_for_storage.base_txn_id =
        increment_map_sequence(txn, table::kBlockTransactions.name, body_for_storage.txn_count);
    Bytes value{body_for_storage.encode()};
    auto key{db::block_key(bn, hash.bytes)};

    auto target = txn.rw_cursor(table::kBlockBodies);
    target->upsert(to_slice(key), to_slice(value));

    write_transactions(txn, body.transactions, body_for_storage.base_txn_id);
}

static ByteView read_senders_raw(ROTxn& txn, const Bytes& key) {
    auto cursor = txn.ro_cursor(table::kSenders);
    auto data{cursor->find(to_slice(key), /*throw_notfound = */ false)};
    return data ? from_slice(data.value) : ByteView();
}

std::vector<evmc::address> read_senders(ROTxn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    auto key{block_key(block_number, hash)};
    return read_senders(txn, key);
}

std::vector<evmc::address> read_senders(ROTxn& txn, const Bytes& key) {
    std::vector<evmc::address> senders{};
    auto data_view{read_senders_raw(txn, key)};
    if (!data_view.empty()) {
        SILKWORM_ASSERT(data_view.length() % kAddressLength == 0);
        senders.resize(data_view.length() / kAddressLength);
        std::memcpy(senders.data(), data_view.data(), data_view.length());
    }
    return senders;
}

void parse_senders(ROTxn& txn, const Bytes& key, std::vector<Transaction>& out) {
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

void write_senders(RWTxn& txn, const evmc::bytes32& hash, const BlockNum& block_number, const Block& block) {
    auto key{db::block_key(block_number, hash.bytes)};
    auto target = txn.rw_cursor(table::kSenders);
    Bytes data;
    for (const auto& block_txn : block.transactions) {
        if (block_txn.from.has_value()) {
            data.append(block_txn.from.value().bytes, kAddressLength);
        } else {
            throw std::runtime_error("Missing senders for block " + std::to_string(block_number));
        }
    }

    target->upsert(to_slice(key), to_slice(data));
}

void write_tx_lookup(RWTxn& txn, const Block& block) {
    auto target = txn.rw_cursor(table::kTxLookup);
    const auto block_number_bytes = db::block_key(block.header.number);
    for (const auto& block_txn : block.transactions) {
        auto tx_key = block_txn.hash();
        target->upsert(to_slice(tx_key), to_slice(block_number_bytes));
    }
}

void write_receipts(RWTxn& txn, const std::vector<silkworm::Receipt>& receipts, const BlockNum& block_number) {
    auto target = txn.rw_cursor(table::kBlockReceipts);
    auto key{db::block_key(block_number)};
    Bytes value{cbor_encode(receipts)};
    target->upsert(to_slice(key), to_slice(value));
}

std::optional<ByteView> read_code(ROTxn& txn, const evmc::bytes32& code_hash) {
    auto cursor = txn.ro_cursor(table::kCode);
    auto key{to_slice(code_hash)};
    auto data{cursor->find(key, /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    return from_slice(data.value);
}

// Erigon FindByHistory for account
static std::optional<ByteView> historical_account(ROTxn& txn, const evmc::address& address, BlockNum block_number) {
    auto cursor = txn.ro_cursor_dup_sort(table::kAccountHistory);
    const Bytes history_key{account_history_key(address, block_number)};
    const auto data{cursor->lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data || !data.key.starts_with(to_slice(address))) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::parse(data.value)};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    cursor->bind(txn, table::kAccountChangeSet);
    const Bytes change_set_key{block_key(*change_block)};
    return find_value_suffix(*cursor, change_set_key, address.bytes);
}

// Erigon FindByHistory for storage
static std::optional<ByteView> historical_storage(ROTxn& txn, const evmc::address& address, uint64_t incarnation,
                                                  const evmc::bytes32& location, BlockNum block_number) {
    auto cursor = txn.ro_cursor_dup_sort(table::kStorageHistory);
    const Bytes history_key{storage_history_key(address, location, block_number)};
    const auto data{cursor->lower_bound(to_slice(history_key), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }

    const ByteView k{from_slice(data.key)};
    SILKWORM_ASSERT(k.length() == kAddressLength + kHashLength + sizeof(BlockNum));

    if (k.substr(0, kAddressLength) != ByteView{address} ||
        k.substr(kAddressLength, kHashLength) != ByteView{location}) {
        return std::nullopt;
    }

    const auto bitmap{bitmap::parse(data.value)};
    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        return std::nullopt;
    }

    cursor->bind(txn, table::kStorageChangeSet);
    const Bytes change_set_key{storage_change_key(*change_block, address, incarnation)};
    return find_value_suffix(*cursor, change_set_key, location.bytes);
}

std::optional<Account> read_account(ROTxn& txn, const evmc::address& address, std::optional<BlockNum> block_num) {
    std::optional<ByteView> encoded{block_num.has_value() ? historical_account(txn, address, block_num.value())
                                                          : std::nullopt};

    if (!encoded.has_value()) {
        auto state_cursor = txn.ro_cursor_dup_sort(table::kPlainState);
        if (auto data{state_cursor->find({address.bytes, sizeof(evmc::address)}, false)}; data.done) {
            encoded.emplace(from_slice(data.value));
        }
    }
    if (!encoded.has_value() || encoded->empty()) {
        return std::nullopt;
    }

    const auto acc_res{Account::from_encoded_storage(encoded.value())};
    success_or_throw(acc_res);
    Account acc{*acc_res};

    if (acc.incarnation > 0 && acc.code_hash == kEmptyHash) {
        // restore code hash
        auto code_cursor = txn.ro_cursor(table::kPlainCodeHash);
        auto key{storage_prefix(address, acc.incarnation)};
        if (auto data{code_cursor->find(to_slice(key), /*throw_notfound*/ false)};
            data.done && data.value.length() == kHashLength) {
            std::memcpy(acc.code_hash.bytes, data.value.data(), kHashLength);
        }
    }

    return acc;
}

evmc::bytes32 read_storage(ROTxn& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<BlockNum> block_num) {
    std::optional<ByteView> val{block_num.has_value()
                                    ? historical_storage(txn, address, incarnation, location, block_num.value())
                                    : std::nullopt};
    if (!val.has_value()) {
        auto cursor = txn.ro_cursor_dup_sort(table::kPlainState);
        auto key{storage_prefix(address, incarnation)};
        val = find_value_suffix(*cursor, key, location.bytes);
    }

    if (!val.has_value()) {
        return {};
    }

    evmc::bytes32 res{};
    SILKWORM_ASSERT(val->length() <= kHashLength);
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

static std::optional<uint64_t> historical_previous_incarnation(ROTxn& txn, const evmc::address& address, BlockNum block_num) {
    std::optional<ByteView> encoded_account{historical_account(txn, address, block_num + 1)};
    if (!encoded_account) {
        return std::nullopt;
    }
    const auto acc_result{Account::from_encoded_storage(encoded_account.value())};
    success_or_throw(acc_result);
    Account account{*acc_result};
    const uint64_t previous_incarnation{account.incarnation > 0 ? account.incarnation - 1 : 0};
    return previous_incarnation;
}

std::optional<uint64_t> read_previous_incarnation(ROTxn& txn, const evmc::address& address,
                                                  std::optional<BlockNum> block_num) {
    if (block_num.has_value()) {
        return historical_previous_incarnation(txn, address, *block_num);
    }

    auto cursor = txn.ro_cursor(table::kIncarnationMap);
    if (auto data{cursor->find(to_slice(address), /*throw_notfound=*/false)}; data.done) {
        SILKWORM_ASSERT(data.value.length() == 8);
        const uint64_t previous_incarnation{endian::load_big_u64(static_cast<uint8_t*>(data.value.data()))};
        return previous_incarnation;
    }
    return std::nullopt;
}

AccountChanges read_account_changes(ROTxn& txn, BlockNum block_num) {
    AccountChanges changes;

    auto cursor = txn.ro_cursor_dup_sort(table::kAccountChangeSet);
    auto key{block_key(block_num)};
    auto data{cursor->find(to_slice(key), /*throw_notfound=*/false)};
    while (data) {
        SILKWORM_ASSERT(data.value.length() >= kAddressLength);
        evmc::address address;
        std::memcpy(address.bytes, data.value.data(), kAddressLength);
        data.value.remove_prefix(kAddressLength);
        changes[address] = db::from_slice(data.value);
        data = cursor->to_current_next_multi(/*throw_notfound=*/false);
    }

    return changes;
}

StorageChanges read_storage_changes(ROTxn& txn, BlockNum block_num) {
    StorageChanges changes;

    const Bytes block_prefix{block_key(block_num)};

    auto cursor = txn.ro_cursor_dup_sort(table::kStorageChangeSet);
    auto key_prefix{to_slice(block_prefix)};
    auto data{cursor->lower_bound(key_prefix, false)};
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
        data = cursor->to_next(/*throw_notfound=*/false);
    }

    return changes;
}

std::optional<ChainConfig> read_chain_config(ROTxn& txn) {
    auto canonical_hashes_cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto data{canonical_hashes_cursor->find(to_slice(block_key(0)), /*throw_notfound=*/false)};
    if (!data) {
        return std::nullopt;
    }
    const auto key{data.value};

    canonical_hashes_cursor->bind(txn, table::kConfig);
    data = canonical_hashes_cursor->find(key, /*throw_notfound=*/false);
    if (!data) {
        return std::nullopt;
    }

    // https://github.com/nlohmann/json/issues/2204
    const auto json = nlohmann::json::parse(data.value.as_string(), nullptr, false);
    return ChainConfig::from_json(json);
}

void update_chain_config(RWTxn& txn, const ChainConfig& config) {
    auto genesis_hash{read_canonical_header_hash(txn, 0)};
    if (!genesis_hash.has_value()) {
        return;
    }
    auto cursor = txn.rw_cursor(db::table::kConfig);
    auto config_data{config.to_json().dump()};
    cursor->upsert(db::to_slice(genesis_hash->bytes), mdbx::slice(config_data.data()));
}

static Bytes head_header_key() {
    std::string table_name = db::table::kHeadHeader.name;
    Bytes key{table_name.begin(), table_name.end()};
    return key;
}

void write_head_header_hash(RWTxn& txn, const evmc::bytes32& hash) {
    write_head_header_hash(txn, hash.bytes);
}

void write_head_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength]) {
    auto target = txn.rw_cursor(table::kHeadHeader);
    Bytes key = head_header_key();
    auto skey = db::to_slice(key);

    target->upsert(skey, to_slice(hash));
}

std::optional<evmc::bytes32> read_head_header_hash(ROTxn& txn) {
    auto cursor = txn.ro_cursor(table::kHeadHeader);
    Bytes key = head_header_key();
    auto skey = db::to_slice(key);
    auto data{cursor->find(skey, /*throw_notfound=*/false)};
    if (!data || data.value.length() != kHashLength) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

std::optional<evmc::bytes32> read_canonical_hash(ROTxn& txn, BlockNum b) {  // throws db exceptions
    auto hashes_table = txn.ro_cursor(db::table::kCanonicalHashes);
    // accessing this table with only b we will get the hash of the canonical block at height b
    auto key = db::block_key(b);
    auto data = hashes_table->find(db::to_slice(key), /*throw_notfound*/ false);
    if (!data) return std::nullopt;  // not found
    assert(data.value.length() == kHashLength);
    return to_bytes32(from_slice(data.value));  // copy
}

void write_canonical_hash(RWTxn& txn, BlockNum b, const evmc::bytes32& hash) {
    Bytes key = db::block_key(b);
    auto skey = db::to_slice(key);
    auto svalue = db::to_slice(hash);

    auto hashes_cursor = txn.rw_cursor(db::table::kCanonicalHashes);
    hashes_cursor->upsert(skey, svalue);
}

void delete_canonical_hash(RWTxn& txn, BlockNum b) {
    auto hashes_cursor = txn.rw_cursor(db::table::kCanonicalHashes);
    Bytes key = db::block_key(b);
    auto skey = db::to_slice(key);
    (void)hashes_cursor->erase(skey);
}

uint64_t increment_map_sequence(RWTxn& txn, const char* map_name, uint64_t increment) {
    uint64_t current_value{read_map_sequence(txn, map_name)};
    if (increment) {
        auto target = txn.rw_cursor(table::kSequence);
        mdbx::slice key(map_name);
        uint64_t new_value{current_value + increment};  // Note ! May overflow
        Bytes new_data(sizeof(uint64_t), '\0');
        endian::store_big_u64(new_data.data(), new_value);
        target->upsert(key, to_slice(new_data));
    }
    return current_value;
}

uint64_t read_map_sequence(ROTxn& txn, const char* map_name) {
    auto target = txn.ro_cursor(table::kSequence);
    mdbx::slice key(map_name);
    auto data{target->find(key, /*throw_notfound=*/false)};
    if (!data.done) {
        return 0;
    }
    if (data.value.length() != sizeof(uint64_t)) {
        throw std::length_error("Bad sequence value in db");
    }
    return endian::load_big_u64(from_slice(data.value).data());
}

uint64_t reset_map_sequence(RWTxn& txn, const char* map_name, uint64_t new_sequence) {
    uint64_t current_sequence{read_map_sequence(txn, map_name)};
    if (new_sequence != current_sequence) {
        auto target = txn.rw_cursor(table::kSequence);
        mdbx::slice key(map_name);
        Bytes new_sequence_buffer(sizeof(uint64_t), '\0');
        endian::store_big_u64(new_sequence_buffer.data(), new_sequence);
        target->upsert(key, to_slice(new_sequence_buffer));
    }
    return current_sequence;
}

const std::string kHeadBlockHash = "headBlockHash";
const std::string kSafeBlockHash = "safeBlockHash";
const std::string kFinalizedBlockHash = "finalizedBlockHash";

std::optional<evmc::bytes32> read_last_fcu_field(ROTxn& txn, const std::string& field) {
    auto cursor = txn.ro_cursor(table::kLastForkchoice);

    Bytes key{field.begin(), field.end()};
    auto skey = db::to_slice(key);

    auto data{cursor->find(skey, /*throw_notfound=*/false)};
    if (!data || data.value.length() != kHashLength) {
        return std::nullopt;
    }
    return to_bytes32(from_slice(data.value));
}

void write_last_fcu_field(RWTxn& txn, const std::string& field, const evmc::bytes32& hash) {
    auto cursor = txn.rw_cursor(table::kLastForkchoice);

    Bytes key{field.begin(), field.end()};
    auto skey = db::to_slice(key);

    cursor->upsert(skey, to_slice(hash));
}

std::optional<evmc::bytes32> read_last_head_block(ROTxn& txn) {
    return read_last_fcu_field(txn, kHeadBlockHash);
}

std::optional<evmc::bytes32> read_last_safe_block(ROTxn& txn) {
    return read_last_fcu_field(txn, kSafeBlockHash);
}

std::optional<evmc::bytes32> read_last_finalized_block(ROTxn& txn) {
    return read_last_fcu_field(txn, kFinalizedBlockHash);
}

void write_last_head_block(RWTxn& txn, const evmc::bytes32& hash) {
    write_last_fcu_field(txn, kHeadBlockHash, hash);
}

void write_last_safe_block(RWTxn& txn, const evmc::bytes32& hash) {
    write_last_fcu_field(txn, kSafeBlockHash, hash);
}

void write_last_finalized_block(RWTxn& txn, const evmc::bytes32& hash) {
    write_last_fcu_field(txn, kFinalizedBlockHash, hash);
}

void DataModel::set_snapshot_repository(snapshot::SnapshotRepository* repository) {
    ensure(repository, "DataModel::set_snapshot_repository: repository is null");
    repository_ = repository;
}

DataModel::DataModel(ROTxn& txn) : txn_{txn} {}

std::optional<ChainConfig> DataModel::read_chain_config() const {
    return db::read_chain_config(txn_);
}

std::optional<ChainId> DataModel::read_chain_id() const {
    const auto chain_config{read_chain_config()};
    std::optional<ChainId> chain_id;
    if (chain_config) {
        chain_id = chain_config->chain_id;
    }
    return chain_id;
}

BlockNum DataModel::highest_block_number() const {
    // Assume last block is likely on db: first lookup there
    const auto header_cursor{txn_.ro_cursor(db::table::kHeaders)};
    const auto data{header_cursor->to_last(/*.throw_not_found*/ false)};
    if (data.done && data.key.size() >= sizeof(uint64_t)) {
        ByteView key = from_slice(data.key);
        ByteView block_num_data = key.substr(0, sizeof(BlockNum));
        BlockNum block_num = endian::load_big_u64(block_num_data.data());
        if (block_num > 0) {  // skip genesis block if present
            return block_num;
        }
    }

    // If none is found on db, then ask the snapshot repository (if any) for highest block
    return repository_ ? repository_->max_block_available() : 0;
}

BlockNum DataModel::highest_frozen_block_number() {
    // Ask the snapshot repository (if any) for highest block
    return repository_ ? repository_->max_block_available() : 0;
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_number, HashAsArray block_hash) const {
    return read_header(block_number, Hash(block_hash));
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_number, const Hash& block_hash) const {
    if (repository_ && block_number <= repository_->max_block_available()) {
        auto header = read_header_from_snapshot(block_number);
        if (header && header->hash() == block_hash) {  // reading using hash avoid this heavy hash calculation
            return header;
        }
        return {};
    } else {
        return db::read_header(txn_, block_number, block_hash);
    }
}

std::optional<BlockHeader> DataModel::read_header(BlockNum block_number) const {
    if (repository_ && block_number <= repository_->max_block_available()) {
        return read_header_from_snapshot(block_number);
    } else {
        auto hash = db::read_canonical_hash(txn_, block_number);
        return db::read_header(txn_, block_number, *hash);
    }
}

std::optional<BlockHeader> DataModel::read_header(const Hash& block_hash) const {
    // Assume recent blocks are more probable: first lookup the block header in the db
    auto block_header{db::read_header(txn_, block_hash)};
    if (block_header) return block_header;

    // Then search for it in the snapshots (if any)
    return read_header_from_snapshot(block_hash);
}

std::optional<BlockNum> DataModel::read_block_number(const Hash& block_hash) const {
    // Assume recent blocks are more probable: first lookup the block in the db
    auto block_number{db::read_block_number(txn_, block_hash)};
    if (block_number) return block_number;

    // Then search for it in the snapshots (if any)
    const auto block_header{read_header_from_snapshot(block_hash)};
    if (block_header) {
        block_number = block_header->number;
    }
    return block_number;
}

std::vector<BlockHeader> DataModel::read_sibling_headers(BlockNum block_number) const {
    std::vector<BlockHeader> sibling_headers;

    // Read all siblings headers at specified height from db
    process_headers_at_height(txn_, block_number, [&](BlockHeader&& header) {
        sibling_headers.push_back(std::move(header));
    });

    // Read block header at specified height from snapshot (if any) just in case
    std::optional<BlockHeader> header = read_header_from_snapshot(block_number);
    if (header) {
        sibling_headers.push_back(std::move(*header));
    }

    return sibling_headers;
}

bool DataModel::read_body(BlockNum height, HashAsArray hash, bool read_senders, BlockBody& body) const {
    // Assume recent blocks are more probable: first lookup the block body in the db
    const bool found = db::read_body(txn_, height, hash, read_senders, body);
    if (found) return found;

    return read_body_from_snapshot(height, read_senders, body);
}

bool DataModel::read_body(const Hash& hash, BlockNum height, BlockBody& body) const {
    return read_body(height, hash.bytes, /*read_senders=*/false, body);
}

bool DataModel::read_body(const Hash& hash, BlockBody& body) const {
    const bool found = db::read_body(txn_, hash, body);
    if (found) return found;

    // Then search for it in the snapshots (if any)
    const auto block_header{read_header_from_snapshot(hash)};
    if (block_header) {
        return read_body(block_header->number, hash.bytes, /*read_senders=*/false, body);
    }

    return false;
}

std::optional<Hash> DataModel::read_canonical_hash(BlockNum height) const {
    return db::read_canonical_hash(txn_, height);
}

std::optional<BlockHeader> DataModel::read_canonical_header(BlockNum height) const {
    const auto canonical_hash{db::read_canonical_hash(txn_, height)};
    if (!canonical_hash) return {};

    return read_header(height, *canonical_hash);
}

bool DataModel::read_canonical_body(BlockNum height, BlockBody& body) const {
    const auto canonical_hash{db::read_canonical_hash(txn_, height)};
    if (!canonical_hash) return {};

    return read_body(*canonical_hash, height, body);
}

bool DataModel::read_canonical_block(BlockNum height, Block& block) const {
    const auto canonical_hash{db::read_canonical_hash(txn_, height)};
    if (!canonical_hash) return {};

    return read_block(*canonical_hash, height, block);
}

bool DataModel::has_body(BlockNum height, HashAsArray hash) const {
    const bool found = db::has_body(txn_, height, hash);
    if (found) return found;

    return is_body_in_snapshot(height);
}

bool DataModel::has_body(BlockNum height, const Hash& hash) const {
    return has_body(height, hash.bytes);
}

bool DataModel::read_block(HashAsSpan hash, BlockNum number, bool read_senders, Block& block) const {
    const bool found = db::read_block(txn_, hash, number, read_senders, block);
    if (found) return found;

    return read_block_from_snapshot(number, read_senders, block);
}

bool DataModel::read_block(const evmc::bytes32& hash, BlockNum number, Block& block) const {
    const bool found = db::read_block(txn_, hash, number, block);
    if (found) return found;

    return read_block_from_snapshot(number, /*read_senders=*/true, block);
}

void DataModel::for_last_n_headers(size_t n, absl::FunctionRef<void(BlockHeader&&)> callback) const {
    constexpr bool throw_notfound{false};

    // Try to read N headers from the database
    size_t read_count{0};
    std::optional<BlockNum> last_read_number_from_db;

    const auto headers_cursor{txn_.ro_cursor(db::table::kHeaders)};
    auto data = headers_cursor->to_last(throw_notfound);
    while (data && read_count < n) {
        // Read header
        BlockHeader header;
        ByteView data_view = db::from_slice(data.value);
        success_or_throw(rlp::decode(data_view, header));
        ++read_count;
        last_read_number_from_db = header.number;
        // Consume header
        callback(std::move(header));
        // Move backward
        data = headers_cursor->to_previous(throw_notfound);
    }
    if (read_count == n) {
        return;
    }

    auto block_number_in_snapshots = repository_ ? repository_->max_block_available() : 0;

    // We've reached the first header in db but still need to read more from snapshots
    if (repository_ && last_read_number_from_db > 0) {
        ensure(*last_read_number_from_db == block_number_in_snapshots + 1,
               "db and snapshot block numbers are not contiguous");
    }

    while (read_count < n) {
        auto header{read_header_from_snapshot(block_number_in_snapshots)};
        if (!header) return;
        ++block_number_in_snapshots;
        ++read_count;
        // Consume header
        callback(std::move(*header));
    }
}

bool DataModel::read_block(BlockNum number, bool read_senders, Block& block) const {
    const auto hash{db::read_canonical_hash(txn_, number)};
    if (!hash) {
        return false;
    }
    return read_block(hash->bytes, number, read_senders, block);
}

bool DataModel::read_block_from_snapshot(BlockNum height, bool read_senders, Block& block) {
    if (!repository_) {
        return false;
    }

    auto block_header{read_header_from_snapshot(height)};
    if (!block_header) return false;

    block.header = std::move(*block_header);

    return read_body_from_snapshot(height, read_senders, block);
}

std::optional<BlockHeader> DataModel::read_header_from_snapshot(BlockNum height) {
    if (!repository_) {
        return {};
    }

    std::optional<BlockHeader> block_header;
    // We know the header snapshot in advance: find it based on target block number
    const auto header_snapshot = repository_->find_header_segment(height);
    if (header_snapshot) {
        block_header = header_snapshot->header_by_number(height);
    }
    return block_header;
}

std::optional<BlockHeader> DataModel::read_header_from_snapshot(const Hash& hash) {
    if (!repository_) {
        return {};
    }

    std::optional<BlockHeader> block_header;
    // We don't know the header snapshot in advance: search for block hash in each header snapshot in reverse order
    repository_->view_header_segments([&](const snapshot::HeaderSnapshot* snapshot) -> bool {
        block_header = snapshot->header_by_hash(hash);
        return block_header.has_value();
    });
    return block_header;
}

bool DataModel::read_body_from_snapshot(BlockNum height, bool read_senders, BlockBody& body) {
    if (!repository_) {
        return false;
    }

    // We know the body snapshot in advance: find it based on target block number
    const auto body_snapshot = repository_->find_body_segment(height);
    if (!body_snapshot) return false;

    auto stored_body = body_snapshot->body_by_number(height);
    if (!stored_body) return false;

    // Skip first and last *system transactions* in block body
    const auto base_txn_id{stored_body->base_txn_id + 1};
    const auto txn_count{stored_body->txn_count >= 2 ? stored_body->txn_count - 2 : stored_body->txn_count};

    std::vector<Transaction> transactions;
    const auto read_ok{read_transactions_from_snapshot(height, base_txn_id, txn_count, read_senders, transactions)};
    if (!read_ok) return false;

    body.transactions = std::move(transactions);
    body.ommers = std::move(stored_body->ommers);
    body.withdrawals = std::move(stored_body->withdrawals);
    return true;
}

bool DataModel::is_body_in_snapshot(BlockNum height) {
    if (!repository_) {
        return false;
    }

    // We know the body snapshot in advance: find it based on target block number
    const auto body_snapshot = repository_->find_body_segment(height);
    if (body_snapshot) {
        const auto stored_body = body_snapshot->body_by_number(height);
        return stored_body.has_value();
    }

    return false;
}

bool DataModel::read_transactions_from_snapshot(BlockNum height, uint64_t base_txn_id, uint64_t txn_count,
                                                bool read_senders, std::vector<Transaction>& txs) {
    txs.reserve(txn_count);
    if (txn_count == 0) {
        return true;
    }

    const auto tx_snapshot = repository_->find_tx_segment(height);
    if (!tx_snapshot) return false;

    txs = tx_snapshot->txn_range(base_txn_id, txn_count, read_senders);

    return true;
}

bool DataModel::read_rlp_transactions_from_snapshot(BlockNum height, std::vector<Bytes>& rlp_txs) {
    const auto body_snapshot = repository_->find_body_segment(height);
    if (body_snapshot) {
        auto stored_body = body_snapshot->body_by_number(height);
        if (!stored_body) return false;

        // Skip first and last *system transactions* in block body
        const auto base_txn_id{stored_body->base_txn_id + 1};
        const auto txn_count{stored_body->txn_count >= 2 ? stored_body->txn_count - 2 : stored_body->txn_count};

        if (txn_count == 0) return true;

        const auto tx_snapshot = repository_->find_tx_segment(height);
        if (!tx_snapshot) return false;

        rlp_txs = tx_snapshot->txn_rlp_range(base_txn_id, txn_count);

        return true;
    }

    return false;
}

bool DataModel::read_rlp_transactions(BlockNum height, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    bool found = db::read_rlp_transactions(txn_, height, hash, rlp_txs);
    if (found) return true;

    return read_rlp_transactions_from_snapshot(height, rlp_txs);
}

std::optional<BlockNum> DataModel::read_tx_lookup(const evmc::bytes32& tx_hash) const {
    auto block_num = read_tx_lookup_from_db(tx_hash);
    if (block_num) {
        return block_num;
    }

    return read_tx_lookup_from_snapshot(tx_hash);
}

std::optional<BlockNum> DataModel::read_tx_lookup_from_db(const evmc::bytes32& tx_hash) const {
    auto cursor = txn_.ro_cursor(table::kTxLookup);
    auto data{cursor->find(to_slice(tx_hash), /*throw_notfound = */ false)};
    if (!data) {
        return std::nullopt;
    }
    return std::stoul(silkworm::to_hex(from_slice(data.value)), nullptr, 16);
}

std::optional<BlockNum> DataModel::read_tx_lookup_from_snapshot(const evmc::bytes32& tx_hash) {
    if (!repository_) {
        return {};
    }

    return repository_->find_block_number(tx_hash);
}

std::optional<intx::uint256> DataModel::read_total_difficulty(BlockNum height, const evmc::bytes32& hash) const {
    return db::read_total_difficulty(txn_, height, hash);
}

std::optional<intx::uint256> DataModel::read_total_difficulty(BlockNum height, HashAsArray hash) const {
    return db::read_total_difficulty(txn_, height, hash);
}

std::optional<intx::uint256> DataModel::read_total_difficulty(ByteView key) const {
    return db::read_total_difficulty(txn_, key);
}

}  // namespace silkworm::db
