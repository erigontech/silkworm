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

//! Return the maximum TxNum in specified \code block_number
Task<TxNum> max_tx_num(kv::api::Transaction& tx, BlockNum block_number, chain::CanonicalBodyForStorageProvider provider);

//! Return the minimum TxNum in specified \code block_number
Task<TxNum> min_tx_num(kv::api::Transaction& tx, BlockNum block_number, chain::CanonicalBodyForStorageProvider provider);

using BlockNumAndTxnNumber = std::pair<BlockNum, TxNum>;

//! Return the first assigned TxNum
Task<BlockNumAndTxnNumber> first_tx_num(kv::api::Transaction& tx);

//! Return the last assigned TxNum
Task<BlockNumAndTxnNumber> last_tx_num(kv::api::Transaction& tx);

}  // namespace silkworm::db::txn
