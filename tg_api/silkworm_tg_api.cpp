/*
   Copyright 2020 The Silkworm Authors

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

#include "silkworm_tg_api.h"

#include <cassert>
#include <gsl/gsl_util>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/execution/execution.hpp>

SILKWORM_EXPORT SilkwormStatusCode silkworm_execute_blocks(MDB_txn* mdb_txn, uint64_t chain_id, uint64_t start_block,
                                                           size_t batch_size, bool write_receipts,
                                                           uint64_t* last_executed_block,
                                                           int* lmdb_error_code) SILKWORM_NOEXCEPT {
    assert(mdb_txn);

    using namespace silkworm;

    const ChainConfig* config{lookup_chain_config(chain_id)};
    if (!config) {
        return kSilkwormUnknownChainId;
    }

    try {
        lmdb::Transaction txn{/*parent=*/nullptr, mdb_txn, /*flags=*/0};
        auto cleanup{gsl::finally([&txn] { *txn.handle() = nullptr; })};  // avoid aborting mdb_txn

        db::Buffer buffer{&txn};

        for (uint64_t block_num{start_block};; ++block_num) {
            std::optional<BlockWithHash> bh{db::read_block(txn, block_num, /*read_senders=*/true)};
            if (!bh) {
                return kSilkwormBlockNotFound;
            }

            std::vector<Receipt> receipts{execute_block(bh->block, buffer)};

            if (write_receipts) {
                buffer.insert_receipts(block_num, receipts);
            }

            if (last_executed_block) {
                *last_executed_block = block_num;
            }

            if (buffer.current_batch_size() >= batch_size) {
                buffer.write_to_db();
                return kSilkwormSuccess;
            }
        };
    } catch (const lmdb::exception& e) {
        if (lmdb_error_code) {
            *lmdb_error_code = e.err();
        }
        return kSilkwormLmdbError;
    } catch (const db::MissingSenders&) {
        return kSilkwormMissingSenders;
    } catch (const ValidationError&) {
        return kSilkwormInvalidBlock;
    } catch (const DecodingError&) {
        return kSilkwormDecodingError;
    } catch (...) {
        return kSilkwormUnknownError;
    }
}
