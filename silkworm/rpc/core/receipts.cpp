/*
   Copyright 2023 The Silkworm Authors

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

#include "receipts.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>

namespace silkworm::rpc::core {

Task<Receipts> get_receipts(const core::rawdb::DatabaseReader& db_reader, const silkworm::BlockWithHash& block_with_hash) {
    const auto cached_receipts = co_await core::rawdb::read_receipts(db_reader, block_with_hash);
    if (cached_receipts) {
        co_return *cached_receipts;
    }

    // If not already present, retrieve receipts by executing transactions
    // auto block = co_await core::rawdb::read_block(db_reader, hash, number);
    // TODO(canepat): implement
    SILK_WARN << "retrieve receipts by executing transactions NOT YET IMPLEMENTED";
    co_return Receipts{};
}

}  // namespace silkworm::rpc::core
