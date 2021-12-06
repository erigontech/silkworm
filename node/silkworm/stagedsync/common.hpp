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

#pragma once
#ifndef SILKWORM_STAGEDSYNC_COMMON_HPP_
#define SILKWORM_STAGEDSYNC_COMMON_HPP_

#include <cstdint>
#include <exception>

#include <magic_enum.hpp>

namespace silkworm::stagedsync {

enum class [[nodiscard]] StageResult{
    kSuccess,                 //
    kUnknownChainId,          //
    kUnknownConsensusEngine,  //
    kBadBlockHash,            //
    kBadChainSequence,        //
    kInvalidRange,            //
    kInvalidProgress,         //
    kInvalidBlock,            //
    kInvalidTransaction,      //
    kMissingSenders,          //
    kDecodingError,           //
    kUnexpectedError,         //
    kUnknownError,            //
    kDbError,                 //
    kAborted,                 //
};

//! \brief Stage execution exception
class StageError : public std::exception {
  public:
    explicit StageError(StageResult err)
        : err_{magic_enum::enum_integer<StageResult>(err)},
          message_{"Stage error : " + std::string(magic_enum::enum_name<StageResult>(err))} {};
    [[maybe_unused]] explicit StageError(StageResult err, std::string message)
        : err_{magic_enum::enum_integer<StageResult>(err)}, message_{std::move(message)} {};
    ~StageError() noexcept override = default;
    [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }
    [[nodiscard]] int err() const noexcept { return err_; }

  protected:
    int err_;
    std::string message_;
};

//! \brief Throws StageError exception when code =! StageResult::kSuccess
//! \param [in] code : The result of a stage operation
inline void success_or_throw(StageResult code) {
    if (code != StageResult::kSuccess) {
        throw StageError(code);
    }
}

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_COMMON_HPP_
