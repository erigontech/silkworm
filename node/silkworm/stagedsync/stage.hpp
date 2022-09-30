/*
   Copyright 2022 The Silkworm Authors

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

#include <cstdint>
#include <exception>
#include <mutex>

#include <magic_enum.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/concurrency/stoppable.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

namespace silkworm::stagedsync {

class StageError;

//! \brief Holds informations across all stages
struct SyncContext {
    SyncContext() = default;
    ~SyncContext() = default;

    // Not copyable nor movable
    SyncContext(const SyncContext&) = delete;
    SyncContext& operator=(const SyncContext&) = delete;

    //! \brief Whether this is first cycle
    bool is_first_cycle{false};

    //! \brief If an unwind operation is requested this member is valued
    std::optional<BlockNum> unwind_point;

    //! \brief After an unwind operation this is valued to last unwind point
    std::optional<BlockNum> previous_unwind_point;

    //! \brief If an unwind operation is requested this member is valued
    std::optional<evmc::bytes32> bad_block_hash;
};

//! \brief Base Stage interface. All stages MUST inherit from this class and MUST override forward / unwind /
//! prune
class Stage : public Stoppable {
  public:
    enum class [[nodiscard]] Result{
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
        kWrongFork,               // The persisted canonical chain must be changed
        kWrongStateRoot,          //
        kUnexpectedError,         //
        kUnknownError,            //
        kDbError,                 //
        kAborted,                 //
        kStoppedByEnv,            // Encountered "STOP_BEFORE_STAGE" env var
        kUnspecified,
    };

    enum class OperationType {
        None,     // Actually no operation running
        Forward,  // Executing Forward
        Unwind,   // Executing Unwind
        Prune,    // Executing Prune
    };
    explicit Stage(SyncContext* sync_context, const char* stage_name, NodeSettings* node_settings);
    virtual ~Stage() = default;

    //! \brief Forward is called when the stage is executed. The main logic of the stage must be here.
    //! \param [in] txn : A db transaction holder
    //! \return Result
    //! \remarks Must be overridden
    [[nodiscard]] virtual Stage::Result forward(db::RWTxn& txn) = 0;

    //! \brief Unwind is called when the stage should be unwound. The unwind logic must be here.
    //! \param [in] txn : A db transaction holder
    //! \param [in] to : New height we need to unwind to
    //! \return Result
    //! \remarks Must be overridden
    [[nodiscard]] virtual Stage::Result unwind(db::RWTxn& txn) = 0;

    //! \brief Prune is called when (part of) stage previously persisted data should be deleted. The pruning logic
    //! must be here.
    //! \param [in] txn : A db transaction holder
    //! \return Result
    [[nodiscard]] virtual Stage::Result prune(db::RWTxn& txn) = 0;

    //! \brief Returns the actual progress recorded into db
    BlockNum get_progress(db::RWTxn& txn);

    //! \brief Returns the actual prune progress recorded into db
    BlockNum get_prune_progress(db::RWTxn& txn);

    //! \brief Updates current stage progress
    void update_progress(db::RWTxn& txn, BlockNum progress);

    //! \brief Sets the prefix for logging lines produced by stage itself
    void set_log_prefix(const std::string& prefix) { log_prefix_ = prefix; };

    //! \brief This function implementation MUST be thread safe as is called asynchronously from ASIO thread
    [[nodiscard]] virtual std::vector<std::string> get_log_progress() { return {}; };

    //! \brief Returns the key name of the stage instance
    [[nodiscard]] const char* name() const { return stage_name_; }

    //! \brief Forces an exception if stage has been requested to stop
    void throw_if_stopping();

  protected:
    SyncContext* sync_context_;                                  // Shared context across stages
    const char* stage_name_;                                     // Human friendly identifier of the stage
    NodeSettings* node_settings_;                                // Pointer to shared node configuration settings
    std::atomic<OperationType> operation_{OperationType::None};  // Actual operation being carried out
    std::mutex sl_mutex_;                                        // To synchronize access by outer sync loop
    std::string log_prefix_;                                     // Log lines prefix holding the progress among stages

    //! \brief Throws if actual block != expected block
    static void check_block_sequence(BlockNum actual, BlockNum expected);
};

//! \brief Stage execution exception
class StageError : public std::exception {
  public:
    explicit StageError(Stage::Result err)
        : err_{magic_enum::enum_integer<Stage::Result>(err)},
          message_{std::string(magic_enum::enum_name<Stage::Result>(err))} {};
    explicit StageError(Stage::Result err, std::string message)
        : err_{magic_enum::enum_integer<Stage::Result>(err)}, message_{std::move(message)} {};
    ~StageError() noexcept override = default;
    [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }
    [[nodiscard]] int err() const noexcept { return err_; }

  protected:
    int err_;
    std::string message_;
};

//! \brief Throws StageError exception when code =! Result::kSuccess
//! \param [in] code : The result of a stage operation
inline void success_or_throw(Stage::Result code) {
    if (code != Stage::Result::kSuccess) {
        throw StageError(code);
    }
}

}  // namespace silkworm::stagedsync
