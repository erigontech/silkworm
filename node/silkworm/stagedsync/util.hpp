/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_STAGEDSYNC_UTIL_HPP_
#define SILKWORM_STAGEDSYNC_UTIL_HPP_

#include <silkworm/common/base.hpp>
#include <silkworm/db/mdbx.hpp>

/*
Part of the compatibility layer with the Erigon DB format;
see its package dbutils.
*/

namespace silkworm::stagedsync {

// clang-format off
enum class [[nodiscard]] StageResult {
    kSuccess,
    kUnknownChainId,
    kUnknownConsensusEngine,
    kBadBlockHash,
    kBadChainSequence,
    kInvalidRange,
    kInvalidProgress,
    kInvalidBlock,
    kInvalidTransaction,
    kMissingSenders,
    kDecodingError,
    kUnexpectedError,
    kUnknownError,
    kDbError,
    kAborted,
};
// clang-format on

void check_stagedsync_error(StageResult code);

//! \brief Converts change set (AccountChangeSet/StorageChangeSet) entry to plain state format.
//! \param [in] key : Change set key.
//! \param [in] value : Change set value.
//! \return Plain state key + previous value of the account or storage.
//! \remarks For storage location is returned as the last part of the key,
//! while technically in PlainState it's the first part of the value.
std::pair<Bytes, Bytes> change_set_to_plain_state_format(ByteView key, ByteView value);

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_UTIL_HPP_
