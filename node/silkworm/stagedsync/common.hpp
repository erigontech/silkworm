/*
    Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/concurrency/stoppable.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>

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
          message_{std::string(magic_enum::enum_name<StageResult>(err))} {};
    explicit StageError(StageResult err, std::string message)
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

//! \brief Base Stage interface. All stages MUST inherit from this class and MUST override forward / unwind /
//! prune
class IStage : public Stoppable {
  public:
    enum class OperationType {
        None,     // Actually no operation running
        Forward,  // Executing Forward
        Unwind,   // Executing Unwind
        Prune,    // Executing Prune
    };
    explicit IStage(const char* stage_name, NodeSettings* node_settings)
        : stage_name_{stage_name}, node_settings_{node_settings} {};
    virtual ~IStage() = default;

    //! \brief Forward is called when the stage is executed. The main logic of the stage must be here.
    //! \param [in] txn : A db transaction holder
    //! \return StageResult
    //! \remarks Must be overridden
    [[nodiscard]] virtual StageResult forward(db::RWTxn& txn) = 0;

    //! \brief Unwind is called when the stage should be unwound. The unwind logic must be here.
    //! \param [in] txn : A db transaction holder
    //! \param [in] to : New height we need to unwind to
    //! \return StageResult
    //! \remarks Must be overridden
    [[nodiscard]] virtual StageResult unwind(db::RWTxn& txn, BlockNum to) = 0;

    //! \brief Prune is called when (part of) stage previously persisted data should be deleted. The pruning logic
    //! must be here.
    //! \param [in] txn : A db transaction holder
    //! \return StageResult
    [[nodiscard]] virtual StageResult prune(db::RWTxn& txn) = 0;

    //! \brief Returns the actual progress recorded into db
    BlockNum get_progress(db::RWTxn& txn);

    //! \brief This function implementation MUST be thread safe as is called asynchronously from ASIO thread
    [[nodiscard]] virtual std::vector<std::string> get_log_progress() = 0;

    //! \brief Returns the key name of the stage instance
    [[nodiscard]] const char* name() const { return stage_name_; }

    //! \brief Forces an exception if stage has been requested to stop
    void throw_if_stopping() { success_or_throw(is_stopping() ? StageResult::kAborted : StageResult::kSuccess); }

  protected:
    const char* stage_name_;
    NodeSettings* node_settings_;
    std::atomic<OperationType> operation_{OperationType::None};

    //! \brief Throws if actual block != expected block
    static void check_block_sequence(BlockNum actual, BlockNum expected);
};

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_COMMON_HPP_
