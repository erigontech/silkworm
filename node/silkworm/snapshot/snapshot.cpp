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

#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm {

namespace fs = std::filesystem;

Snapshot::Snapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
    : path_(std::move(path)), block_from_(block_from), block_to_(block_to), decoder_{path_} {
    if (block_to < block_from) {
        throw std::logic_error{"invalid block range: block_to less than block_from"};
    }
}

void Snapshot::reopen_segment() {
    close_segment();
    // TODO(canepat) consider extracting MemoryMappedFile from Decompressor and keep it here
    // TODO(canepat) so that we open/close the file more explicitly and wrap Decompressor around it
    // Open decompressor that in turn opens mapped file
    decoder_.open();
}

bool Snapshot::for_each_item(const Snapshot::WordItemFunc& fn) {
    return decoder_.read_ahead([fn](Decompressor::Iterator it) -> bool {
        uint64_t word_count{0};
        WordItem item{};
        while (it.has_next()) {
            const uint64_t next_offset = it.next(item.value);
            item.position = word_count;
            SILK_DEBUG << "for_each_item item: offset=" << item.offset << " position=" << item.position
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

void Snapshot::close() {
    close_segment();
    close_index();
}

void Snapshot::close_segment() {
    // Close decompressor that in turn closes mapped file
    decoder_.close();
}

bool HeaderSnapshot::for_each_header(const Walker& walker) {
    return for_each_item([walker](const WordItem& item) -> bool {
        ByteView encoded_header{item.value.data() + 1, item.value.length() - 1};
        SILK_DEBUG << "for_each_header encoded_header: " << to_hex(encoded_header);
        BlockHeader header;
        const auto decode_result = rlp::decode(encoded_header, header);
        SILK_DEBUG << "for_each_header decode_result: " << magic_enum::enum_name<>(decode_result);
        if (decode_result != DecodingResult::kOk) return false;
        SILK_DEBUG << "for_each_header header number: " << header.number << " hash:" << to_hex(header.hash());
        return walker(&header);
    });
}

void HeaderSnapshot::reopen_index() {
    // TODO(canepat): implement
}

void HeaderSnapshot::close_index() {
    // TODO(canepat): implement
}

bool BodySnapshot::for_each_body(const Walker& walker) {
    return for_each_item([&](const WordItem& item) -> bool {
        const BlockNum number = block_from_ + item.position;
        ByteView body_rlp{item.value.data(), item.value.length()};
        SILK_DEBUG << "for_each_body number: " << number << " body_rlp: " << to_hex(body_rlp);
        db::detail::BlockBodyForStorage body;
        const auto decode_result = db::detail::decode_stored_block_body(body_rlp, body);
        SILK_DEBUG << "for_each_body decode_result: " << magic_enum::enum_name<>(decode_result);
        if (decode_result != DecodingResult::kOk) return false;
        SILK_DEBUG << "for_each_body number: " << number << " txn_count: " << body.txn_count << " base_txn_id:" << body.base_txn_id;
        return walker(number, &body);
    });
}

void BodySnapshot::reopen_index() {
    // TODO(canepat): implement
}

void BodySnapshot::close_index() {
    // TODO(canepat): implement
}

void TransactionSnapshot::reopen_index() {
    // TODO(canepat): implement
}

void TransactionSnapshot::close_index() {
    // TODO(canepat): implement
}

}  // namespace silkworm
