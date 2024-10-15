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

#include "txn_to_block_index.hpp"

#include "txs_and_bodies_query.hpp"

namespace silkworm::snapshots {

static IndexInputDataQuery::Iterator::value_type query_entry(TxsAndBodiesQuery::Iterator& it) {
    return {
        .key_data = it->tx_buffer,
        .value = it->block_number,
    };
}

IndexInputDataQuery::Iterator TransactionToBlockIndexInputDataQuery::begin() {
    auto impl_it = std::make_shared<TxsAndBodiesQuery::Iterator>(query_.begin());
    return IndexInputDataQuery::Iterator{this, impl_it, query_entry(*impl_it)};
}

IndexInputDataQuery::Iterator TransactionToBlockIndexInputDataQuery::end() {
    auto impl_it = std::make_shared<TxsAndBodiesQuery::Iterator>(query_.end());
    return IndexInputDataQuery::Iterator{this, impl_it, query_entry(*impl_it)};
}

size_t TransactionToBlockIndexInputDataQuery::keys_count() {
    return query_.expected_tx_count();
}

std::pair<std::shared_ptr<void>, IndexInputDataQuery::Iterator::value_type>
TransactionToBlockIndexInputDataQuery::next_iterator(std::shared_ptr<void> it_impl) {
    auto& it_impl_ref = *reinterpret_cast<TxsAndBodiesQuery::Iterator*>(it_impl.get());
    ++it_impl_ref;
    return {it_impl, query_entry(it_impl_ref)};
}

bool TransactionToBlockIndexInputDataQuery::equal_iterators(
    std::shared_ptr<void> lhs_it_impl,
    std::shared_ptr<void> rhs_it_impl) const {
    auto lhs = reinterpret_cast<TxsAndBodiesQuery::Iterator*>(lhs_it_impl.get());
    auto rhs = reinterpret_cast<TxsAndBodiesQuery::Iterator*>(rhs_it_impl.get());
    return (*lhs == *rhs);
}

IndexBuilder TransactionToBlockIndex::make(
    SnapshotPath bodies_segment_path,
    std::optional<MemoryMappedRegion> bodies_segment_region,
    SnapshotPath segment_path,
    std::optional<MemoryMappedRegion> segment_region,
    BlockNum first_block_num) {
    auto txs_amount = TransactionIndex::compute_txs_amount(bodies_segment_path, bodies_segment_region);
    const uint64_t first_tx_id = txs_amount.first;
    const uint64_t expected_tx_count = txs_amount.second;

    auto descriptor = make_descriptor(segment_path, first_block_num, first_tx_id);

    TxsAndBodiesQuery data_query{
        std::move(segment_path),
        segment_region,
        std::move(bodies_segment_path),
        bodies_segment_region,
        first_block_num,
        first_tx_id,
        expected_tx_count,
    };

    auto query = std::make_unique<TransactionToBlockIndexInputDataQuery>(std::move(data_query));
    return IndexBuilder{std::move(descriptor), std::move(query)};
}

}  // namespace silkworm::snapshots
