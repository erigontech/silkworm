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

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/stoppable.hpp>
#include <silkworm/node/db/etl_mdbx_collector.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/db/tables.hpp>

namespace silkworm::stagedsync {

class StageError;

//! \brief Holds information across all stages
struct SyncContext {
    SyncContext() = default;
    ~SyncContext() = default;

    SyncContext(const SyncContext&) = delete;             // not copyable
    SyncContext& operator=(const SyncContext&) = delete;  // not copyable

    bool is_first_cycle{true};  // true at start-up (fist sync or sync after a long pause)

    BlockNum target_height{0};

    std::optional<BlockNum> unwind_point;  // if valued sync requires an unwind to this point
    std::optional<BlockNum> previous_unwind_point;

    std::optional<evmc::bytes32> bad_block_hash;  // valued if we encountered a bad block
};

//! \brief Base Stage interface. All stages MUST inherit from this class and MUST override forward / unwind /
//! prune
class Stage : public Stoppable {
  public:
    enum class [[nodiscard]] Result {
        kSuccess,                 // valid chain
        kUnknownProtocolRuleSet,  //
        kBadChainSequence,        //
        kInvalidProgress,         //
        kInvalidBlock,            // invalid chain
        kInvalidTransaction,      //
        kDecodingError,           //
        kWrongFork,               // invalid chain: the persisted canonical chain must be changed
        kWrongStateRoot,          // invalid chain
        kUnexpectedError,         //
        kDbError,                 //
        kAborted,                 //
        kStoppedByEnv,            // valid chain: encountered "STOP_BEFORE_STAGE" env var
        kUnspecified,
    };

    enum class OperationType {
        None,     // Actually no operation running
        Forward,  // Executing Forward
        Unwind,   // Executing Unwind
        Prune,    // Executing Prune
    };

    Stage(SyncContext* sync_context, const char* stage_name);

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
    BlockNum get_progress(db::ROTxn& txn);

    //! \brief Returns the actual prune progress recorded into db
    BlockNum get_prune_progress(db::ROTxn& txn);

    //! \brief Set the prune progress into db
    //! \param [in] txn : A R/W db transaction
    //! \param [in] progress : Block number reached by pruning process
    void set_prune_progress(db::RWTxn& txn, BlockNum progress);

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
    std::atomic<OperationType> operation_{OperationType::None};  // Actual operation being carried out
    std::mutex sl_mutex_;                                        // To synchronize access by outer sync loop
    std::string log_prefix_;                                     // Log lines prefix holding the progress among stages

    //! \brief Throws if actual block != expected block
    static void check_block_sequence(BlockNum actual, BlockNum expected);
};

//! \brief Stage execution exception
class StageError : public std::exception {
  public:
    explicit StageError(Stage::Result err);
    explicit StageError(Stage::Result err, std::string message);
    ~StageError() noexcept override = default;
    [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }
    [[nodiscard]] int err() const noexcept { return err_; }

  protected:
    int err_;
    std::string message_;
};

// Throw StageError exception when result indicates a failure
inline void success_or_throw(Stage::Result code) {
    if (code != Stage::Result::kSuccess) {
        throw StageError(code);
    }
}
// Return true if result indicates that an unwind operation is needed
inline bool unwind_needed(Stage::Result result) {
    return (result == Stage::Result::kWrongFork || result == Stage::Result::kInvalidBlock);
}

}  // namespace silkworm::stagedsync
