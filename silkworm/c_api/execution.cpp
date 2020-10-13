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

#include <gsl/gsl_util>
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
    auto _ = gsl::finally([&txn] { *txn.handle() = nullptr; });  // avoid aborting mdb_txn

    try {
        std::optional<BlockWithHash> bh{db::read_block(txn, block_num)};
        if (!bh) {
            return kSilkwormBlockNotFound;
        }

        std::vector<evmc::address> senders{db::read_senders(txn, block_num, bh->hash)};
        if (senders.size() != bh->block.transactions.size()) {
            return kSilkwormMissingSenders;
        }
        for (size_t i{0}; i < senders.size(); ++i) {
            bh->block.transactions[i].from = senders[i];
        }

        state::Reader reader{txn};
        db::Buffer buffer{&txn};
        IntraBlockState state{&reader};
        ExecutionProcessor processor{bh->block, state, buffer};

        std::vector<Receipt> receipts{processor.execute_block()};

        state.write_block(buffer);
        buffer.write_to_db(block_num);
    } catch (const lmdb::exception& e) {
        if (lmdb_error_code) {
            *lmdb_error_code = e.err();
        }
        return kSilkwormLmdbError;
    } catch (const ValidationError& err) {
        return kSilkwormInvalidBlock;
    } catch (const DecodingError& err) {
        return kSilkwormDecodingError;
    } catch (...) {
        return kSilkwormUnknownError;
    }

    return kSilkwormSuccess;
}
