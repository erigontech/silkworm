// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <exception>
#include <mutex>

#include <silkworm/db/datastore/kvdb/etl_mdbx_collector.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/stoppable.hpp>

namespace silkworm::db {
using silkworm::datastore::kvdb::MapConfig;
using silkworm::datastore::kvdb::ROTxn;
using silkworm::datastore::kvdb::RWTxn;
}  // namespace silkworm::db

namespace silkworm::stagedsync {

class StageError;

//! \brief Holds information across all stages
struct SyncContext {
    SyncContext() = default;
    ~SyncContext() = default;

    SyncContext(const SyncContext&) = delete;             // not copyable
    SyncContext& operator=(const SyncContext&) = delete;  // not copyable

    bool is_first_cycle{true};  // true at start-up (fist sync or sync after a long pause)

    BlockNum target_block_num{0};

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
        kNone,     // Actually no operation running
        kForward,  // Executing Forward
        kUnwind,   // Executing Unwind
        kPrune,    // Executing Prune
    };

    Stage(SyncContext* sync_context, const char* stage_name);

    //! \brief Forward is called when the stage is executed. The main logic of the stage must be here.
    //! \param [in] txn : A db transaction holder
    //! \return Result
    //! \remarks Must be overridden
    virtual Stage::Result forward(db::RWTxn& txn) = 0;

    //! \brief Unwind is called when the stage should be unwound. The unwind logic must be here.
    //! \param [in] txn : A db transaction holder
    //! \return Result
    //! \remarks Must be overridden
    virtual Stage::Result unwind(db::RWTxn& txn) = 0;

    //! \brief Prune is called when (part of) stage previously persisted data should be deleted. The pruning logic
    //! must be here.
    //! \param [in] txn : A db transaction holder
    //! \return Result
    virtual Stage::Result prune(db::RWTxn& txn) = 0;

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
    virtual std::vector<std::string> get_log_progress() { return {}; };

    //! \brief Returns the key name of the stage instance
    const char* name() const { return stage_name_; }

    //! \brief Forces an exception if stage has been requested to stop
    void throw_if_stopping();

  protected:
    // Shared context across stages
    SyncContext* sync_context_;
    const char* stage_name_;
    std::atomic<OperationType> operation_{OperationType::kNone};
    // To synchronize access by outer sync loop
    std::mutex sl_mutex_;
    std::string log_prefix_;

    //! \brief Throws if actual block != expected block
    static void check_block_sequence(BlockNum actual, BlockNum expected);
};

//! \brief Stage execution exception
class StageError : public std::exception {
  public:
    explicit StageError(Stage::Result err);
    explicit StageError(Stage::Result err, std::string message);
    ~StageError() noexcept override = default;
    const char* what() const noexcept override { return message_.c_str(); }
    int err() const noexcept { return err_; }

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
