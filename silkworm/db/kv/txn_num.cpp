/*
   Copyright 2024 The Silkworm Authors

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

#include "txn_num.hpp"

#include <stdexcept>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/infra/common/async_binary_search.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

#include "../tables.hpp"

namespace silkworm::db::txn {

using kv::api::KeyValue;
using kv::api::Transaction;

static Task<TxNum> last_tx_num_for_block(const std::shared_ptr<kv::api::Cursor>& max_tx_num_cursor,
                                         BlockNum block_number,
                                         chain::CanonicalBodyForStorageProvider canonical_body_for_storage_provider) {
    const auto block_number_key = block_key(block_number);
    const auto key_value = co_await max_tx_num_cursor->seek_exact(block_number_key);
    if (key_value.value.empty()) {
        SILKWORM_ASSERT(canonical_body_for_storage_provider);
        Bytes block_body_data = co_await canonical_body_for_storage_provider(block_number);
        ByteView block_body_data_view{block_body_data};
        const auto stored_body = unwrap_or_throw(decode_stored_block_body(block_body_data_view));
        co_return stored_body.base_txn_id + stored_body.txn_count - 1;
    }
    if (key_value.value.size() != sizeof(TxNum)) {
        throw std::length_error("Bad TxNum value size " + std::to_string(key_value.value.size()) + " in db");
    }
    co_return endian::load_big_u64(key_value.value.data());
}

static std::pair<BlockNum, TxNum> kv_to_block_num_and_tx_num(const KeyValue& key_value) {
    if (key_value.key.empty() || key_value.value.empty()) {
        return std::make_pair(0, 0);
    }
    if (key_value.key.size() != sizeof(BlockNum)) {
        throw std::length_error("Bad BlockNum key size " + std::to_string(key_value.key.size()) + " in db");
    }
    if (key_value.value.size() != sizeof(TxNum)) {
        throw std::length_error("Bad TxNum value size " + std::to_string(key_value.value.size()) + " in db");
    }
    return std::make_pair(endian::load_big_u64(key_value.key.data()), endian::load_big_u64(key_value.value.data()));
}

Task<TxNum> max_tx_num(Transaction& tx, BlockNum block_number, chain::CanonicalBodyForStorageProvider provider) {
    const auto max_tx_num_cursor = co_await tx.cursor(table::kMaxTxNumName);
    co_return co_await last_tx_num_for_block(max_tx_num_cursor, block_number, provider);
}

Task<TxNum> min_tx_num(Transaction& tx, BlockNum block_number, chain::CanonicalBodyForStorageProvider provider) {
    if (block_number == 0) {
        co_return 0;
    }
    const auto max_tx_num_cursor = co_await tx.cursor(table::kMaxTxNumName);
    co_return (co_await last_tx_num_for_block(max_tx_num_cursor, (block_number - 1), provider) + 1);
}

Task<BlockNumAndTxnNumber> first_tx_num(Transaction& tx) {
    const auto max_tx_num_cursor = co_await tx.cursor(table::kMaxTxNumName);
    const auto first_key_value = co_await max_tx_num_cursor->first();
    co_return kv_to_block_num_and_tx_num(first_key_value);
}

Task<BlockNumAndTxnNumber> last_tx_num(Transaction& tx) {
    const auto max_tx_num_cursor = co_await tx.cursor(table::kMaxTxNumName);
    const auto last_key_value = co_await max_tx_num_cursor->last();
    co_return kv_to_block_num_and_tx_num(last_key_value);
}

Task<std::optional<BlockNum>> block_num_from_tx_num(kv::api::Transaction& tx,
                                                    TxNum tx_num,
                                                    chain::CanonicalBodyForStorageProvider provider) {
    const auto max_tx_num_cursor = co_await tx.cursor(table::kMaxTxNumName);
    const auto last_key_value = co_await max_tx_num_cursor->last();
    const auto [last_block_num, _] = kv_to_block_num_and_tx_num(last_key_value);
    const auto block_num = co_await binary_search(last_block_num + 1, [&](size_t i) -> Task<bool> {
        const auto max_tx_num = co_await last_tx_num_for_block(max_tx_num_cursor, i, provider);
        co_return max_tx_num >= tx_num;
    });
    if (block_num > last_block_num) {
        co_return std::nullopt;
    }
    co_return block_num;
}

}  // namespace silkworm::db::txn
