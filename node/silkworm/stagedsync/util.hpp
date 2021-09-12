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

void success_or_throw(StageResult code);

// Convert changesets key and value pair to plain state format
std::pair<Bytes, Bytes> convert_to_db_format(const ByteView& key, const ByteView& value);

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_UTIL_HPP_
