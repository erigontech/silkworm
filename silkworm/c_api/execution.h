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

#ifndef SILKWORM_C_API_EXECUTION_H_
#define SILKWORM_C_API_EXECUTION_H_

#include <evmc/utils.h>
#include <lmdb/lmdb.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum SilkwormStatusCode {
    kSilkwormSuccess = 0,
    kSilkwormUnknownChainId = 1,
    kSilkwormLmdbError = 2,
    kSilkwormBlockNotFound = 3,
    kSilkwormMissingSenders = 4,
    kSilkwormInvalidBlock = 5,
    kSilkwormDecodingError = 6,
    kSilkwormUnknownError = -1
};

/** @brief Executes a given block and writes resulting changes into the database.
 *
 * The function assumes that the state in the database is the one that should be at the begining of the block.
 * Only PLAIN-CST2, PLAIN-ACS and PLAIN-SCS tables are written to.
 * @param[in] txn Valid read-write LMDB transaction. May not be NULL.
 * This function does not commit nor abort the transaction.
 * @param[in] chain_id EIP-155 chain ID. kSilkwormUnknownChainId is returned in case of an unknown or unsupported chain.
 * @param[in] block_number The height of the block to execute.
 * @param[out] lmdb_error_code If an LMDB error occurs (this function returns kSilkwormLmdbError)
 * and lmdb_error_code isn't NULL, it's populated with the relevant LMDB error code.
 * @return A non-zero error value on failure and kSilkwormSuccess(=0) on success.
 */
SilkwormStatusCode silkworm_execute_block(MDB_txn* txn, uint64_t chain_id, uint64_t block_number,
                                          int* lmdb_error_code) EVMC_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif  // SILKWORM_C_API_EXECUTION_H_
