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

#include "silkworm_api.h"

#include <cassert>

#include <gsl/gsl_util>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>

namespace silkworm::db {

//! \brief ROTxnUnmanaged wraps an *unmanaged* read-only transaction, which means the underlying transaction
//! lifecycle is not touched by this class. This implies that this class does not abort the transaction.
class ROTxnUnmanaged : public ROTxn, protected ::mdbx::txn {
  public:
    explicit ROTxnUnmanaged(MDBX_txn* ptr) : ROTxn{static_cast<::mdbx::txn&>(*this)}, ::mdbx::txn{ptr} {}
    ~ROTxnUnmanaged() override = default;

    void abort() override {}
};

//! \brief ROTxnUnmanaged wraps an *unmanaged* read-write transaction, which means the underlying transaction
//! lifecycle is not touched by this class. This implies that this class does not commit nor abort the transaction.
class RWTxnUnmanaged : public RWTxn, protected ::mdbx::txn {
  public:
    explicit RWTxnUnmanaged(MDBX_txn* ptr) : RWTxn{static_cast<::mdbx::txn&>(*this)}, ::mdbx::txn{ptr} {}
    ~RWTxnUnmanaged() override = default;

    void abort() override {}
    void commit_and_renew() override {}
    void commit_and_stop() override {}
};

}  // namespace silkworm::db

SILKWORM_EXPORT
SilkwormStatusCode silkworm_execute_blocks(MDBX_txn* mdbx_txn, uint64_t chain_id, uint64_t start_block, uint64_t max_block,
                                           uint64_t batch_size, bool /*write_receipts*/, uint64_t* last_executed_block,
                                           int* mdbx_error_code) SILKWORM_NOEXCEPT {
    assert(mdbx_txn);

    using namespace silkworm;

    const auto chain_info = lookup_known_chain(chain_id);
    if (!chain_info) {
        return kSilkwormUnknownChainId;
    }
    const ChainConfig* chain_config{chain_info->second};

    try {
        db::RWTxnUnmanaged txn{mdbx_txn};
        // mdbx::txn txn{mdbx_txn};
        // lmdb::Transaction txn{/*parent=*/nullptr, mdb_txn, /*flags=*/0};
        // auto cleanup{gsl::finally([&txn] { (*txn).handle() = nullptr; })};  // avoid aborting mdb_txn

        db::Buffer buffer{txn, /*prune_history_threshold=*/0};
        db::DataModel data_model{txn};

        // TODO(canepat) prefetch blocks like in execution stage

        for (uint64_t block_num{start_block}; block_num <= max_block; ++block_num) {
            Block block;
            const bool success{data_model.read_block(block_num, /*read_senders=*/true, block)};
            if (!success) {
                return kSilkwormBlockNotFound;
            }

            const auto validation_result{execute_block(block, buffer, *chain_config)};
            if (validation_result != ValidationResult::kOk) {
                return kSilkwormInvalidBlock;
            }

            // TODO(canepat) check if writing receipts to state is necessary
            // std::vector<Receipt> receipts{execute_block(bh->block, buffer)};
            /*if (write_receipts) {
                buffer.insert_receipts(block_num, receipts);
            }*/

            if (last_executed_block) {
                *last_executed_block = block_num;
            }

            if (block_num % 1000 == 0) {
                SILK_INFO << "Blocks <= " << block_num << " executed";
            }

            // TODO(canepat) was buffer.current_batch_size() so check execution stage
            if (buffer.current_batch_state_size() >= batch_size) {
                buffer.write_to_db();
                return kSilkwormSuccess;
            }
        }

        buffer.write_to_db();
        return kSilkwormSuccess;
    } catch (const mdbx::exception& e) {
        if (mdbx_error_code) {
            *mdbx_error_code = e.error().code();
        }
        return kSilkwormMdbxError;
    } catch (const DecodingError&) {
        return kSilkwormDecodingError;
    } catch (...) {
        return kSilkwormUnknownError;
    }
}
