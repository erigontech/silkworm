// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage.hpp"

#include <magic_enum.hpp>

#include <silkworm/db/stages.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db::stages;

Stage::Stage(SyncContext* sync_context, std::string_view stage_name)
    : sync_context_{sync_context}, stage_name_{stage_name} {}

BlockNum Stage::get_progress(db::ROTxn& txn) {
    return read_stage_progress(txn, stage_name_);
}

BlockNum Stage::get_prune_progress(db::ROTxn& txn) {
    return read_stage_prune_progress(txn, stage_name_);
}

void Stage::set_prune_progress(db::RWTxn& txn, BlockNum progress) {
    write_stage_prune_progress(txn, stage_name_, progress);
}

void Stage::update_progress(db::RWTxn& txn, BlockNum progress) {
    write_stage_progress(txn, stage_name_, progress);
}

void Stage::check_block_sequence(BlockNum actual, BlockNum expected) {
    if (actual != expected) {
        const std::string what{"bad block sequence : expected " + std::to_string(expected) + " got " +
                               std::to_string(actual)};
        throw StageError(Stage::Result::kBadChainSequence, what);
    }
}

void Stage::throw_if_stopping() {
    if (is_stopping()) throw StageError(Stage::Result::kAborted);
}

StageError::StageError(Stage::Result err)
    : err_{magic_enum::enum_integer<Stage::Result>(err)},
      message_{std::string(magic_enum::enum_name<Stage::Result>(err))} {}

StageError::StageError(Stage::Result err, std::string message)
    : err_{magic_enum::enum_integer<Stage::Result>(err)}, message_{std::move(message)} {}

}  // namespace silkworm::stagedsync
