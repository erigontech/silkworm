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

#include "snapshot.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm::snapshot {

//! Convert the specified decoding result into its string representation
inline std::string to_string(DecodingResult result) {
    std::string s;
    if (!result.has_value()) {
        s.append(magic_enum::enum_name(result.error()));
    }
    return s;
}

Snapshot::Snapshot(SnapshotPath path)
    : path_(std::move(path)), decoder_{path_.path()} {}

Snapshot::Snapshot(SnapshotPath path, MemoryMappedRegion segment_region)
    : path_(std::move(path)), decoder_{path_.path(), segment_region} {}

uint8_t* Snapshot::memory_file_address() const {
    const auto memory_file{decoder_.memory_file()};
    if (!memory_file) return nullptr;
    return memory_file->address();
}

std::size_t Snapshot::memory_file_size() const {
    const auto memory_file{decoder_.memory_file()};
    if (!memory_file) return 0;
    return memory_file->length();
}

void Snapshot::reopen_segment() {
    close_segment();

    // Open decompressor that opens the mapped file in turns
    decoder_.open();
}

bool Snapshot::for_each_item(const Snapshot::WordItemFunc& fn) {
    return decoder_.read_ahead([fn](huffman::Decompressor::Iterator it) -> bool {
        uint64_t word_count{0};
        WordItem item{};
        while (it.has_next()) {
            const uint64_t next_offset = it.next(item.value);
            item.position = word_count;
            SILK_TRACE << "for_each_item item: offset=" << item.offset << " position=" << item.position
                       << " value=" << to_hex(item.value);
            const bool result = fn(item);
            if (!result) return false;
            ++word_count;
            item.offset = next_offset;
            item.value.clear();
        }
        return true;
    });
}

std::optional<Snapshot::WordItem> Snapshot::next_item(uint64_t offset, ByteView prefix) const {
    SILK_TRACE << "Snapshot::next_item offset: " << offset;
    auto data_iterator = decoder_.make_iterator();
    data_iterator.reset(offset);

    std::optional<WordItem> item;
    if (!data_iterator.has_next()) {
        return item;
    }
    if (not prefix.empty() and not data_iterator.has_prefix(prefix)) {
        return item;
    }

    item = WordItem{};
    try {
        item->offset = data_iterator.next(item->value);
    } catch (const std::runtime_error& re) {
        SILK_WARN << "Snapshot::next_item invalid offset: " << offset << " what: " << re.what();
        return {};
    }

    return item;
}

void Snapshot::close() {
    close_segment();
    close_index();
}

void Snapshot::close_segment() {
    // Close decompressor that closes the mapped file in turns
    decoder_.close();
}

HeaderSnapshot::HeaderSnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

HeaderSnapshot::HeaderSnapshot(SnapshotPath path, MappedHeadersSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment), idx_header_hash_region_{mapped.header_hash_index} {}

HeaderSnapshot::~HeaderSnapshot() {
    close();
}

bool HeaderSnapshot::for_each_header(const Walker& walker) {
    return for_each_item([this, walker](const WordItem& item) -> bool {
        BlockHeader header;
        const auto decode_ok = decode_header(item, header);
        if (!decode_ok) {
            return false;
        }
        return walker(&header);
    });
}

std::optional<BlockHeader> HeaderSnapshot::next_header(uint64_t offset, std::optional<Hash> hash) const {
    // Get the next data item at specified offset, optionally checking if it starts with block hash first byte
    const auto item = hash ? next_item(offset, {hash->bytes, 1}) : next_item(offset);
    std::optional<BlockHeader> header;
    if (!item) {
        return header;
    }
    header = BlockHeader{};
    const auto decode_ok = decode_header(*item, *header);
    if (!decode_ok) {
        return {};
    }
    return header;
}

std::optional<BlockHeader> HeaderSnapshot::header_by_hash(const Hash& block_hash) const {
    if (!idx_header_hash_) {
        return {};
    }

    // First, get the header ordinal position in snapshot by using block hash as MPHF index
    const auto block_header_position = idx_header_hash_->lookup(block_hash);
    SILK_TRACE << "HeaderSnapshot::header_by_hash block_hash: " << block_hash.to_hex() << " block_header_position: " << block_header_position;
    // Then, get the header offset in snapshot by using ordinal lookup
    const auto block_header_offset = idx_header_hash_->ordinal_lookup(block_header_position);
    SILK_TRACE << "HeaderSnapshot::header_by_hash block_header_offset: " << block_header_offset;
    // Finally, read the next header at specified offset
    auto header = next_header(block_header_offset, block_hash);
    // We *must* ensure that the retrieved header hash matches because there is no way to know if key exists in MPHF
    if (header and header->hash() != block_hash) {
        header.reset();
    }
    return header;
}

std::optional<BlockHeader> HeaderSnapshot::header_by_number(BlockNum block_height) const {
    if (!idx_header_hash_ or block_height < path_.block_from() or block_height >= path_.block_to()) {
        return {};
    }

    // First, calculate the header ordinal position relative to the first block height within snapshot
    const auto block_header_position = block_height - idx_header_hash_->base_data_id();
    // Then, get the header offset in snapshot by using ordinal lookup
    const auto block_header_offset = idx_header_hash_->ordinal_lookup(block_header_position);
    // Finally, read the next header at specified offset
    return next_header(block_header_offset);
}

bool HeaderSnapshot::decode_header(const Snapshot::WordItem& item, BlockHeader& header) const {
    // First byte in data is first byte of header hash.
    ensure(!item.value.empty(), "HeaderSnapshot: hash first byte missing at offset=" + std::to_string(item.offset));

    // Skip hash first byte to obtain encoded header RLP data
    ByteView encoded_header{item.value.data() + 1, item.value.length() - 1};
    const auto decode_result = rlp::decode(encoded_header, header);
    if (!decode_result) {
        SILK_TRACE << "decode_header offset: " << item.offset << " error: " << magic_enum::enum_name(decode_result.error());
        return false;
    }

    ensure(header.number >= path_.block_from(),
           "HeaderSnapshot: number=" + std::to_string(header.number) + " < block_from=" + std::to_string(path_.block_from()));
    return true;
}

void HeaderSnapshot::reopen_index() {
    ensure(decoder_.is_open(), "HeaderSnapshot: segment not open, call reopen_segment");

    close_index();

    const auto header_index_path = path().index_file();
    if (header_index_path.exists()) {
        idx_header_hash_ = std::make_unique<succinct::RecSplitIndex>(header_index_path.path(), idx_header_hash_region_);
        if (idx_header_hash_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(header_index_path.path());
            ensure(removed, "HeaderSnapshot: cannot remove index file");
            close_index();
        }
    }
}

void HeaderSnapshot::close_index() {
    idx_header_hash_.reset();
}

BodySnapshot::BodySnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

BodySnapshot::BodySnapshot(SnapshotPath path, MappedBodiesSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment), idx_body_number_region_{mapped.block_num_index} {}

BodySnapshot::~BodySnapshot() {
    close();
}

bool BodySnapshot::for_each_body(const Walker& walker) {
    return for_each_item([&](const WordItem& item) -> bool {
        db::detail::BlockBodyForStorage body;
        success_or_throw(decode_body(item, body));
        const BlockNum number = path_.block_from() + item.position;
        return walker(number, &body);
    });
}

std::pair<uint64_t, uint64_t> BodySnapshot::compute_txs_amount() {
    uint64_t first_tx_id{0}, last_tx_id{0}, last_txs_amount{0};

    const bool read_ok = for_each_body([&](BlockNum number, const StoredBlockBody* body) {
        if (number == path_.block_from()) {
            first_tx_id = body->base_txn_id;
        }
        if (number == path_.block_to() - 1) {
            last_tx_id = body->base_txn_id;
            last_txs_amount = body->txn_count;
        }
        return true;
    });
    if (!read_ok) throw std::runtime_error{"error computing txs amount in: " + path_.path().string()};
    if (first_tx_id == 0 && last_tx_id == 0) throw std::runtime_error{"empty body snapshot: " + path_.path().string()};

    SILK_TRACE << "first_tx_id: " << first_tx_id << " last_tx_id: " << last_tx_id << " last_txs_amount: " << last_txs_amount;

    return {first_tx_id, last_tx_id + last_txs_amount - first_tx_id};
}

std::optional<StoredBlockBody> BodySnapshot::next_body(uint64_t offset) const {
    const auto item = next_item(offset);
    std::optional<StoredBlockBody> stored_body;
    if (!item) {
        return stored_body;
    }
    stored_body = StoredBlockBody{};
    const auto decode_ok = decode_body(*item, *stored_body);
    if (!decode_ok) {
        return {};
    }
    ensure(stored_body->base_txn_id >= idx_body_number_->base_data_id(),
           path().index_file().filename() + " has wrong base data ID for base txn ID: " + std::to_string(stored_body->base_txn_id));
    return stored_body;
}

std::optional<StoredBlockBody> BodySnapshot::body_by_number(BlockNum block_height) const {
    if (!idx_body_number_ or block_height < idx_body_number_->base_data_id()) {
        return {};
    }

    // First, calculate the body ordinal position relative to the first block height within snapshot
    const auto block_body_position = block_height - idx_body_number_->base_data_id();
    // Then, get the body offset in snapshot by using ordinal lookup
    const auto block_body_offset = idx_body_number_->ordinal_lookup(block_body_position);
    // Finally, read the next body at specified offset
    return next_body(block_body_offset);
}

DecodingResult BodySnapshot::decode_body(const Snapshot::WordItem& item, StoredBlockBody& body) {
    ByteView body_rlp{item.value.data(), item.value.length()};
    SILK_TRACE << "decode_body offset: " << item.offset << " body_rlp: " << to_hex(body_rlp);
    const auto result = db::detail::decode_stored_block_body(body_rlp, body);
    SILK_TRACE << "decode_body offset: " << item.offset << " txn_count: " << body.txn_count << " base_txn_id:" << body.base_txn_id;
    return result;
}

void BodySnapshot::reopen_index() {
    ensure(decoder_.is_open(), "BodySnapshot: segment not open, call reopen_segment");

    close_index();

    const auto body_index_path = path().index_file();
    if (body_index_path.exists()) {
        idx_body_number_ = std::make_unique<succinct::RecSplitIndex>(body_index_path.path(), idx_body_number_region_);
        if (idx_body_number_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(body_index_path.path());
            ensure(removed, "BodySnapshot: cannot remove index file");
            close_index();
        }
    }
}

void BodySnapshot::close_index() {
    idx_body_number_.reset();
}

TransactionSnapshot::TransactionSnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

TransactionSnapshot::TransactionSnapshot(SnapshotPath path, MappedTransactionsSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment),
      idx_txn_hash_region_{mapped.tx_hash_index},
      idx_txn_hash_2_block_region_{mapped.tx_hash_2_block_index} {}

TransactionSnapshot::~TransactionSnapshot() {
    close();
}

// Skip first byte of tx hash plus sender address length for transaction decoding
constexpr int kTxRlpDataOffset{1 + kAddressLength};

[[nodiscard]] std::optional<Transaction> TransactionSnapshot::next_txn(uint64_t offset, std::optional<Hash> hash) const {
    // Get the next data item at specified offset, optionally checking if it starts with txn hash first byte
    const auto item = hash ? next_item(offset, {hash->bytes, 1}) : next_item(offset);
    std::optional<Transaction> transaction;
    if (!item) {
        return transaction;
    }
    // Decode transaction from the extracted data item
    transaction = Transaction{};
    const auto decode_ok = decode_txn(*item, *transaction);
    if (!decode_ok) {
        return {};
    }
    return transaction;
}

std::optional<Transaction> TransactionSnapshot::txn_by_hash(const Hash& txn_hash) const {
    if (!idx_txn_hash_) {
        return {};
    }

    // First, get the transaction ordinal position in snapshot by using block hash as MPHF index
    const auto txn_position = idx_txn_hash_->lookup(txn_hash);
    // Then, get the transaction offset in snapshot by using ordinal lookup
    const auto txn_offset = idx_txn_hash_->ordinal_lookup(txn_position);
    // Finally, read the next transaction at specified offset
    auto txn = next_txn(txn_offset, txn_hash);
    // We *must* ensure that the retrieved txn hash matches because there is no way to know if key exists in MPHF
    if (txn and txn->hash() != txn_hash) {
        return {};
    }
    return txn;
}

std::optional<Transaction> TransactionSnapshot::txn_by_id(uint64_t txn_id) const {
    if (!idx_txn_hash_) {
        return {};
    }

    // First, calculate the transaction ordinal position relative to the first transaction ID within snapshot
    const auto txn_position = txn_id - idx_txn_hash_->base_data_id();
    // Then, get the transaction offset in snapshot by using ordinal lookup
    const auto txn_offset = idx_txn_hash_->ordinal_lookup(txn_position);
    // Finally, read the next transaction at specified offset
    return next_txn(txn_offset);
}

std::optional<BlockNum> TransactionSnapshot::block_num_by_txn_hash(const Hash& txn_hash) const {
    if (!idx_txn_hash_2_block_) {
        return {};
    }

    // First, lookup the entire txn to check that the retrieved txn hash matches (no way to know if key exists in MPHF)
    const auto transaction{txn_by_hash(txn_hash)};
    if (!transaction) {
        return {};
    }

    // Finally, get the block number using dedicated MPHF index
    return idx_txn_hash_2_block_->lookup(txn_hash);
}

std::vector<Transaction> TransactionSnapshot::txn_range(uint64_t base_txn_id, uint64_t txn_count, bool read_senders) const {
    std::vector<Transaction> transactions;
    transactions.reserve(txn_count);

    for_each_txn(base_txn_id, txn_count, [&transactions, read_senders](uint64_t i, ByteView senders_data, ByteView tx_rlp) -> bool {
        ByteView tx_payload = slice_tx_payload(tx_rlp);

        Transaction transaction;
        const auto payload_result = rlp::decode_transaction(tx_payload, transaction, rlp::Eip2718Wrapping::kBoth);
        ensure(payload_result.has_value(),
               "TransactionSnapshot: cannot decode tx payload: " + to_hex(tx_payload) + " i: " + std::to_string(i) +
                   " error: " + to_string(payload_result));

        if (read_senders) {
            transaction.set_sender(bytes_to_address(senders_data));
        }

        transactions.push_back(std::move(transaction));
        return true;
    });

    return transactions;
}

std::vector<Bytes> TransactionSnapshot::txn_rlp_range(uint64_t base_txn_id, uint64_t txn_count) const {
    std::vector<Bytes> rlp_txs;
    rlp_txs.reserve(txn_count);

    for_each_txn(base_txn_id, txn_count, [&rlp_txs](uint64_t /*i*/, ByteView /*senders_data*/, ByteView tx_rlp) -> bool {
        ByteView tx_payload = slice_tx_payload(tx_rlp);
        rlp_txs.emplace_back(tx_payload);
        return true;
    });

    return rlp_txs;
}

std::pair<ByteView, ByteView> TransactionSnapshot::slice_tx_data(const WordItem& item) {
    const auto& buffer{item.value};
    const auto buffer_size{buffer.size()};
    SILK_TRACE << "slice_tx_data offset: " << item.offset << " buffer: " << to_hex(buffer);

    ensure(buffer_size >= kTxRlpDataOffset, "TransactionSnapshot: too short record: " + std::to_string(buffer_size));

    // Skip first byte in data as it is first byte of transaction hash
    ByteView senders_data{buffer.data() + 1, kAddressLength};
    ByteView tx_rlp{buffer.data() + kTxRlpDataOffset, buffer_size - kTxRlpDataOffset};

    SILK_TRACE << "slice_tx_data offset: " << item.offset << " tx_hash_first_byte: " << to_hex(buffer[0])
               << " senders_data: " << to_hex(senders_data) << " tx_rlp: " << to_hex(tx_rlp);

    return {senders_data, tx_rlp};
}

ByteView TransactionSnapshot::slice_tx_payload(ByteView tx_rlp) {
    ByteView tx_envelope{tx_rlp};

    rlp::Header tx_header;
    TransactionType tx_type{};
    const auto envelope_result = rlp::decode_transaction_header_and_type(tx_envelope, tx_header, tx_type);
    ensure(envelope_result.has_value(),
           "TransactionSnapshot: cannot decode tx envelope: " + to_hex(tx_envelope) + " error: " + to_string(envelope_result));

    const std::size_t tx_payload_offset = tx_type == TransactionType::kLegacy ? 0 : (tx_rlp.length() - tx_header.payload_length);
    ByteView tx_payload{tx_rlp.substr(tx_payload_offset)};

    return tx_payload;
}

//! Decode transaction from snapshot word. Format is: tx_hash_1byte + sender_address_20byte + tx_rlp_bytes
DecodingResult TransactionSnapshot::decode_txn(const WordItem& item, Transaction& tx) {
    auto [senders_data, tx_rlp] = slice_tx_data(item);
    const auto result = rlp::decode(tx_rlp, tx);
    tx.set_sender(bytes_to_address(senders_data));  // Must happen after rlp::decode because it resets sender
    return result;
}

void TransactionSnapshot::for_each_txn(uint64_t base_txn_id, uint64_t txn_count, const Walker& walker) const {
    if (!idx_txn_hash_ or txn_count == 0) {
        return;
    }

    ensure(base_txn_id >= idx_txn_hash_->base_data_id(),
           path().index_file().filename() + " has wrong base data ID for base txn ID: " + std::to_string(base_txn_id));

    // First, calculate the first transaction ordinal position relative to the base transaction within snapshot
    const auto first_txn_position = base_txn_id - idx_txn_hash_->base_data_id();

    // Then, get the first transaction offset in snapshot by using ordinal lookup
    const auto first_txn_offset = idx_txn_hash_->ordinal_lookup(first_txn_position);

    // Finally, iterate over each encoded transaction item
    for (uint64_t i{0}, offset{first_txn_offset}; i < txn_count; ++i) {
        const auto item = next_item(offset);
        ensure(item.has_value(), "TransactionSnapshot: record not found at offset=" + std::to_string(offset));

        auto [senders_data, tx_rlp] = slice_tx_data(*item);

        const bool go_on{walker(i, senders_data, tx_rlp)};
        if (!go_on) return;

        offset = item->offset;
    }
}

void TransactionSnapshot::reopen_index() {
    ensure(decoder_.is_open(), "TransactionSnapshot: segment not open, call reopen_segment");

    close_index();

    const auto tx_hash_index_path = path().index_file_for_type(SnapshotType::transactions);
    if (tx_hash_index_path.exists()) {
        idx_txn_hash_ = std::make_unique<succinct::RecSplitIndex>(tx_hash_index_path.path(), idx_txn_hash_region_);
        if (idx_txn_hash_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(tx_hash_index_path.path());
            ensure(removed, "TransactionSnapshot: cannot remove tx_hash index file");
            close_index();
        }
    }

    const auto tx_hash_2_block_index_path = path().index_file_for_type(SnapshotType::transactions_to_block);
    if (tx_hash_2_block_index_path.exists()) {
        idx_txn_hash_2_block_ = std::make_unique<succinct::RecSplitIndex>(tx_hash_2_block_index_path.path(), idx_txn_hash_2_block_region_);
        if (idx_txn_hash_2_block_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(tx_hash_2_block_index_path.path());
            ensure(removed, "TransactionSnapshot: cannot remove tx_hash_2_block index file");
            close_index();
        }
    }
}

void TransactionSnapshot::close_index() {
    idx_txn_hash_.reset();
    idx_txn_hash_2_block_.reset();
}

}  // namespace silkworm::snapshot
