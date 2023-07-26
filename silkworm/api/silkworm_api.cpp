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
#include <vector>

#include <gsl/util>

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
                                           uint64_t batch_size, bool write_receipts, uint64_t* last_executed_block,
                                           int* mdbx_error_code) SILKWORM_NOEXCEPT {
    assert(mdbx_txn);

    using namespace silkworm;

    if (start_block > max_block) {
        return kSilkwormInvalidBlockRange;
    }
    const auto chain_info = lookup_known_chain(chain_id);
    if (!chain_info) {
        return kSilkwormUnknownChainId;
    }
    const ChainConfig* chain_config{chain_info->second};

    try {
        // Wrap MDBX txn into an internal *unmanaged* txn, i.e. MDBX txn is only used but neither aborted nor committed
        db::RWTxnUnmanaged txn{mdbx_txn};

        // TODO(txn and snapshot+index memory-mapped files in silkworm_init API)
        snapshot::SnapshotRepository snapshot_repo;
        snapshot_repo.reopen_folder();
        db::DataModel::set_snapshot_repository(&snapshot_repo);

        db::Buffer state_buffer{txn, /*prune_history_threshold=*/0};
        db::DataModel access_layer{txn};

        // Transform batch size limit into gas units (Ggas = Giga gas, Tgas = Tera gas)
        const size_t gas_max_history_size{batch_size * 1_Kibi / 2};  // 512MB -> 256Ggas roughly
        const size_t gas_max_batch_size{gas_max_history_size * 20};  // 256Ggas -> 5Tgas roughly

        // Preload all requested block from storage, i.e. from MDBX database or snapshots
        std::vector<Block> prefetched_blocks;
        prefetched_blocks.reserve(max_block - start_block);
        for (BlockNum block_number{start_block}; block_number <= max_block; ++block_number) {
            prefetched_blocks.emplace_back();
            const bool success{access_layer.read_block(block_number, /*read_senders=*/true, prefetched_blocks.back())};
            if (!success) {
                return kSilkwormBlockNotFound;
            }
        }

        size_t gas_history_size{0};
        size_t gas_batch_size{0};
        for (const auto& block : prefetched_blocks) {
            std::vector<Receipt> receipts;
            const auto validation_result{execute_block(block, state_buffer, *chain_config, receipts)};
            if (validation_result != ValidationResult::kOk) {
                return kSilkwormInvalidBlock;
            }

            if (write_receipts) {
                state_buffer.insert_receipts(block.header.number, receipts);
            }

            if (last_executed_block) {
                *last_executed_block = block.header.number;
            }

            if (block.header.number % 1000 == 0) {
                SILK_INFO << "Blocks <= " << block.header.number << " executed";
            }

            // Flush whole state buffer or just history if we've reached the target batch sizes in gas units
            if (gas_batch_size >= gas_max_batch_size) {
                SILK_TRACE << log::Args{"buffer", "state", "size", human_size(state_buffer.current_batch_state_size())};
                state_buffer.write_to_db();
                gas_batch_size = 0;
            } else if (gas_history_size >= gas_max_history_size) {
                SILK_TRACE << log::Args{"buffer", "history", "size", human_size(state_buffer.current_batch_state_size())};
                state_buffer.write_history_to_db();
                gas_history_size = 0;
            }
        }

        state_buffer.write_to_db();
        return kSilkwormSuccess;
    } catch (const mdbx::exception& e) {
        if (mdbx_error_code) {
            *mdbx_error_code = e.error().code();
        }
        return kSilkwormMdbxError;
    } catch (const DecodingError&) {
        return kSilkwormDecodingError;
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        return kSilkwormUnknownError;
    } catch (...) {
        return kSilkwormUnknownError;
    }
}
