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

#include "execution.h"

#include <silkworm/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/execution/processor.hpp>

SilkwormStatusCode silkworm_execute_block(MDB_txn* mdb_txn, uint64_t chain_id, uint64_t block_num,
                                          int* lmdb_error_code) EVMC_NOEXCEPT {
    using namespace silkworm;

    const ChainConfig* config{lookup_chain_config(chain_id)};
    if (!config) {
        return kSilkwormUnknownChainId;
    }

    lmdb::Transaction txn{/*parent=*/nullptr, mdb_txn, /*flags=*/0};

    try {
        std::optional<BlockWithHash> bh{db::read_block(txn, block_num)};
        if (!bh) {
            *txn.handle() = nullptr;  // avoid aborting mdb_txn
            return kSilkwormBlockNotFound;
        }

        std::vector<evmc::address> senders{db::read_senders(txn, block_num, bh->hash)};
        if (senders.size() != bh->block.transactions.size()) {
            *txn.handle() = nullptr;  // avoid aborting mdb_txn
            return kSilkwormMissingSenders;
        }
        for (size_t i{0}; i < senders.size(); ++i) {
            bh->block.transactions[i].from = senders[i];
        }

        // TODO(Andrew) non-historical reader
        state::Reader reader{txn, block_num};
        IntraBlockState state{&reader};
        ExecutionProcessor processor{bh->block, state, &reader};

        std::vector<Receipt> receipts{processor.execute_block()};

        state::Writer writer{};
        state.write_block(writer);
        writer.write_to_db(txn);
    } catch (const lmdb::exception& e) {
        if (lmdb_error_code) {
            *lmdb_error_code = e.err();
        }
        *txn.handle() = nullptr;  // avoid aborting mdb_txn
        return kSilkwormLmdbError;
    } catch (const ValidationError& err) {
        *txn.handle() = nullptr;  // avoid aborting mdb_txn
        return kSilkwormInvalidBlock;
    } catch (const DecodingError& err) {
        *txn.handle() = nullptr;  // avoid aborting mdb_txn
        return kSilkwormDecodingError;
    } catch (...) {
        *txn.handle() = nullptr;  // avoid aborting mdb_txn
        return kSilkwormUnknownError;
    }

    *txn.handle() = nullptr;  // avoid aborting mdb_txn
    return kSilkwormSuccess;
}
