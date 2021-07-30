/*
   Copyright 2021 The Silkworm Authors

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

#include <filesystem>

#include <boost/endian/conversion.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace fs = std::filesystem;

StageResult stage_blockhashes(TransactionManager &txn, const std::filesystem::path &etl_path) {
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);
    uint32_t block_number{0};

    // We take data from header table and transform it and put it in blockhashes table
    auto canonical_hashes_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};

    auto last_processed_block_number{db::stages::get_stage_progress(*txn, db::stages::kBlockHashesKey)};
    auto expected_block_number{last_processed_block_number + 1};
    uint32_t blocks_processed_count{0};

    // Extract
    SILKWORM_LOG(LogLevel::Info) << "Started BlockHashes Extraction" << std::endl;

    auto header_key{db::block_key(expected_block_number)};
    auto header_data{canonical_hashes_table.find(db::to_slice(header_key), /*throw_notfound*/ false)};
    while (header_data) {
        auto reached_block_number{boost::endian::load_big_u64(static_cast<uint8_t *>(header_data.key.iov_base))};
        if (reached_block_number != expected_block_number) {
            // Something wrong with db
            // Blocks are out of sequence for any reason
            // Should not happen but you never know
            SILKWORM_LOG(LogLevel::Error) << "Bad headers sequence. Expected " << expected_block_number << " got "
                                          << reached_block_number << std::endl;
            return StageResult::kBadChainSequence;
        }

        if (header_data.value.length() != kHashLength) {
            SILKWORM_LOG(LogLevel::Error) << "Bad header hash for block " << expected_block_number << std::endl;
            return StageResult::kBadBlockHash;
        }

        etl::Entry etl_entry{Bytes(static_cast<uint8_t *>(header_data.value.iov_base), header_data.value.iov_len),
                             Bytes(static_cast<uint8_t *>(header_data.key.iov_base), header_data.key.iov_len)};
        collector.collect(etl_entry);

        // Save last processed block_number and expect next in sequence
        ++blocks_processed_count;
        block_number = expected_block_number++;
        canonical_hashes_table.to_next(/*throw_notfound*/ false);
    }
    canonical_hashes_table.close();

    SILKWORM_LOG(LogLevel::Info) << "Entries Collected << " << blocks_processed_count << std::endl;

    // Proceed only if we've done something
    if (blocks_processed_count) {
        SILKWORM_LOG(LogLevel::Info) << "Started BlockHashes Loading" << std::endl;

        /*
         * If we're on first sync then we shouldn't have any records in target
         * table. For this reason we can apply MDB_APPEND to load as
         * collector (with no transform) ensures collected entries
         * are already sorted. If instead target table contains already
         * some data the only option is to load in upsert mode as we
         * cannot guarantee keys are sorted amongst different calls
         * of this stage
         */
        auto target_table{db::open_cursor(*txn, db::table::kHeaderNumbers)};
        auto target_table_rcount{txn->get_map_stat(target_table.map()).ms_entries};
        MDBX_put_flags_t db_flags{target_table_rcount ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items with no transform (may throw)
        collector.load(target_table, nullptr, db_flags, /* log_every_percent = */ 10);

        // Update progress height with last processed block
        db::stages::set_stage_progress(*txn, db::stages::kBlockHashesKey, block_number);

        txn.commit();

    } else {
        SILKWORM_LOG(LogLevel::Info) << "Nothing to process" << std::endl;
    }

    SILKWORM_LOG(LogLevel::Info) << "All Done" << std::endl;

    return StageResult::kSuccess;
}

}  // namespace silkworm::stagedsync
