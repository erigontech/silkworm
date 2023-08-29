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

#include <memory>
#include <vector>

#include <boost/circular_buffer.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>

using namespace silkworm;

static MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf) {
    return {mmf.memory_address, mmf.memory_length};
}

SILKWORM_EXPORT int silkworm_init(SilkwormHandle** handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    const auto snapshot_repository = new snapshot::SnapshotRepository{};
    db::DataModel::set_snapshot_repository(snapshot_repository);
    *handle = reinterpret_cast<SilkwormHandle*>(snapshot_repository);
    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_add_snapshot(SilkwormHandle* handle, SilkwormChainSnapshot* snapshot) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!snapshot) {
        return SILKWORM_INVALID_SNAPSHOT;
    }
    const auto snapshot_repository = reinterpret_cast<snapshot::SnapshotRepository*>(handle);

    const SilkwormHeadersSnapshot& hs = snapshot->headers;
    const auto headers_segment_path = snapshot::SnapshotPath::parse(hs.segment.file_path);
    if (!headers_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshot::MappedHeadersSnapshot mapped_h_snapshot{
        .segment = make_region(hs.segment),
        .header_hash_index = make_region(hs.header_hash_index)};
    auto headers_snapshot = std::make_unique<snapshot::HeaderSnapshot>(*headers_segment_path, mapped_h_snapshot);
    headers_snapshot->reopen_segment();
    headers_snapshot->reopen_index();

    const SilkwormBodiesSnapshot& bs = snapshot->bodies;
    const auto bodies_segment_path = snapshot::SnapshotPath::parse(bs.segment.file_path);
    if (!bodies_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshot::MappedBodiesSnapshot mapped_b_snapshot{
        .segment = make_region(bs.segment),
        .block_num_index = make_region(bs.block_num_index)};
    auto bodies_snapshot = std::make_unique<snapshot::BodySnapshot>(*bodies_segment_path, mapped_b_snapshot);
    bodies_snapshot->reopen_segment();
    bodies_snapshot->reopen_index();

    const SilkwormTransactionsSnapshot& ts = snapshot->transactions;
    const auto transactions_segment_path = snapshot::SnapshotPath::parse(ts.segment.file_path);
    if (!transactions_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshot::MappedTransactionsSnapshot mapped_t_snapshot{
        .segment = make_region(ts.segment),
        .tx_hash_index = make_region(ts.tx_hash_index),
        .tx_hash_2_block_index = make_region(ts.tx_hash_2_block_index)};
    auto transactions_snapshot = std::make_unique<snapshot::TransactionSnapshot>(*transactions_segment_path, mapped_t_snapshot);
    transactions_snapshot->reopen_segment();
    transactions_snapshot->reopen_index();

    snapshot::SnapshotBundle bundle{
        .headers_snapshot_path = *headers_segment_path,
        .headers_snapshot = std::move(headers_snapshot),
        .bodies_snapshot_path = *bodies_segment_path,
        .bodies_snapshot = std::move(bodies_snapshot),
        .tx_snapshot_path = *transactions_segment_path,
        .tx_snapshot = std::move(transactions_snapshot)};
    snapshot_repository->add_snapshot_bundle(std::move(bundle));
    return SILKWORM_OK;
}

SILKWORM_EXPORT
int silkworm_execute_blocks(SilkwormHandle* handle, MDBX_txn* mdbx_txn, uint64_t chain_id, uint64_t start_block, uint64_t max_block,
                            uint64_t batch_size, bool write_change_sets, bool write_receipts, bool write_call_traces,
                            uint64_t* last_executed_block, int* mdbx_error_code) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!mdbx_txn) {
        return SILKWORM_INVALID_MDBX_TXN;
    }
    if (start_block > max_block) {
        return SILKWORM_INVALID_BLOCK_RANGE;
    }
    if (write_change_sets || write_call_traces) {
        return SILKWORM_NOT_IMPLEMENTED_ERROR;  // Flags for writing state changes and call traces not yet supported
    }
    const auto chain_info = lookup_known_chain(chain_id);
    if (!chain_info) {
        return SILKWORM_UNKNOWN_CHAIN_ID;
    }
    const ChainConfig* chain_config{chain_info->second};

    try {
        // Wrap MDBX txn into an internal *unmanaged* txn, i.e. MDBX txn is only used but neither aborted nor committed
        db::RWTxnUnmanaged txn{mdbx_txn};

        db::Buffer state_buffer{txn, /*prune_history_threshold=*/0};
        db::DataModel access_layer{txn};

        static constexpr size_t kCacheSize{5'000};
        AnalysisCache analysis_cache{kCacheSize};
        ObjectPool<evmone::ExecutionState> state_pool;

        // Transform batch size limit into gas units (Ggas = Giga gas, Tgas = Tera gas)
        const size_t gas_max_history_size{batch_size * 1_Kibi / 2};  // 512MB -> 256Ggas roughly
        const size_t gas_max_batch_size{gas_max_history_size * 20};  // 256Ggas -> 5Tgas roughly

        // Preload requested blocks in batches from storage, i.e. from MDBX database or snapshots
        static constexpr size_t kMaxPrefetchedBlocks{10240};
        boost::circular_buffer<Block> prefetched_blocks{/*buffer_capacity=*/kMaxPrefetchedBlocks};

        size_t gas_history_size{0};
        size_t gas_batch_size{0};
        for (BlockNum block_number{start_block}; block_number <= max_block; ++block_number) {
            if (prefetched_blocks.empty()) {
                const auto num_blocks{std::min(size_t(max_block - block_number + 1), kMaxPrefetchedBlocks)};
                SILK_TRACE << "Prefetching " << num_blocks << " blocks start";
                for (BlockNum n{block_number}; n < block_number + num_blocks; ++n) {
                    prefetched_blocks.push_back();
                    const bool success{access_layer.read_block(n, /*read_senders=*/true, prefetched_blocks.back())};
                    if (!success) {
                        return SILKWORM_BLOCK_NOT_FOUND;
                    }
                }
                SILK_TRACE << "Prefetching " << num_blocks << " blocks done";
            }
            const Block& block{prefetched_blocks.front()};

            std::vector<Receipt> receipts;
            const auto validation_result{execute_block(block, analysis_cache, state_pool, state_buffer, *chain_config, receipts)};
            if (validation_result != ValidationResult::kOk) {
                return SILKWORM_INVALID_BLOCK;
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

            prefetched_blocks.pop_front();

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
        return SILKWORM_OK;
    } catch (const mdbx::exception& e) {
        if (mdbx_error_code) {
            *mdbx_error_code = e.error().code();
        }
        return SILKWORM_MDBX_ERROR;
    } catch (const DecodingError&) {
        return SILKWORM_DECODING_ERROR;
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        return SILKWORM_INTERNAL_ERROR;
    } catch (...) {
        return SILKWORM_UNKNOWN_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_fini(SilkwormHandle* handle) SILKWORM_NOEXCEPT {
    const auto snapshot_repository = reinterpret_cast<snapshot::SnapshotRepository*>(handle);
    if (!snapshot_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    delete snapshot_repository;
    return SILKWORM_OK;
}
