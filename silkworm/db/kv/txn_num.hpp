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

#pragma once

#include <cstdint>
#include <optional>
#include <tuple>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/chain/providers.hpp>

#include "../kv/api/transaction.hpp"

namespace silkworm::db::txn {

//! TxNum represents the monotonically increasing unique numbering of blockchain transactions in range [0, inf)
//! TxNum is contiguous (no holes) and canonical, i.e. universal among all client nodes
//! \see txnum.go in Erigon
using TxNum = TxnId;

//! Return the maximum TxNum in specified \code block_num
Task<TxNum> max_tx_num(kv::api::Transaction& tx, BlockNum block_num, chain::CanonicalBodyForStorageProvider provider);

//! Return the minimum TxNum in specified \code block_num
Task<TxNum> min_tx_num(kv::api::Transaction& tx, BlockNum block_num, chain::CanonicalBodyForStorageProvider provider);

using BlockNumAndTxnNumber = std::pair<BlockNum, TxNum>;

//! Return the first assigned TxNum
Task<BlockNumAndTxnNumber> first_tx_num(kv::api::Transaction& tx);

//! Return the last assigned TxNum
Task<BlockNumAndTxnNumber> last_tx_num(kv::api::Transaction& tx);

//! Return the number of the block with max txn number at least equal to given \code tx_num
Task<std::optional<BlockNum>> block_num_from_tx_num(kv::api::Transaction& tx,
                                                    TxNum tx_num,
                                                    chain::CanonicalBodyForStorageProvider provider);

struct TransactionNums {
    TxnId txn_id{0};
    BlockNum block_num{0};
    uint32_t txn_index{0};
    bool final_txn{false};
    bool block_changed{false};
};

using PaginatedTimestampStream = kv::api::PaginatedStream<kv::api::Timestamp>;

class PaginatedTransactionInfoIterator : public kv::api::PaginatedIterator<TransactionNums> {
  public:
    PaginatedTransactionInfoIterator(PaginatedTimestampStream stream,
                                     bool ascending,
                                     kv::api::Transaction& tx,
                                     db::chain::CanonicalBodyForStorageProvider& provider)
        : stream_(std::move(stream)), ascending_(ascending), tx_(tx), provider_(provider) {}

    Task<bool> has_next() override {
        return stream_->has_next();
    }
    Task<std::optional<TransactionNums>> next() override;

  private:
    PaginatedTimestampStream stream_;
    bool ascending_;
    kv::api::Transaction& tx_;
    db::chain::CanonicalBodyForStorageProvider& provider_;
    BlockNum block_num_{0};
    TxNum min_txn_num_{0};
    TxNum max_txn_num_{0};
};

kv::api::PaginatedStream<TransactionNums> make_txn_nums_stream(PaginatedTimestampStream stream,
                                                               bool ascending,
                                                               kv::api::Transaction& tx,
                                                               db::chain::CanonicalBodyForStorageProvider& provider);
}  // namespace silkworm::db::txn
