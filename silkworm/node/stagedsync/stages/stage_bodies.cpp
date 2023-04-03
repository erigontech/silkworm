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

#include "stage_bodies.hpp"

#include <thread>

#include <silkworm/core/consensus/base/engine.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/measure.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/stages.hpp>

namespace silkworm::stagedsync {

BodiesStage::BodyDataModel::BodyDataModel(db::RWTxn& tx, BlockNum bodies_stage_height, const ChainConfig& chain_config)
    : consensus_engine_{consensus::engine_factory(chain_config)},
      chain_state_{tx, /*prune_history_threshold=*/0, /*historical_block=null*/} {
    initial_height_ = bodies_stage_height;
    highest_height_ = bodies_stage_height;
}

BlockNum BodiesStage::BodyDataModel::initial_height() const { return initial_height_; }
BlockNum BodiesStage::BodyDataModel::highest_height() const { return highest_height_; }
bool BodiesStage::BodyDataModel::unwind_needed() const { return unwind_needed_; }
BlockNum BodiesStage::BodyDataModel::unwind_point() const { return unwind_point_; }
Hash BodiesStage::BodyDataModel::bad_block() const { return bad_block_; }
void BodiesStage::BodyDataModel::set_preverified_height(BlockNum height) { preverified_height_ = height; }

// update_tables has the responsibility to update all tables related with the block that is passed as parameter
// Right now there is no table that need to be updated but the name of the method is retained because it makes a pair
// with the same method in the HeadersStages::HeaderDataModel class
void BodiesStage::BodyDataModel::update_tables(const Block& block) {
    Hash block_hash = block.header.hash();  // save cpu
    BlockNum block_num = block.header.number;

    auto validation_result = ValidationResult::kOk;

    // Body validation
    if (block_num > preverified_height_) {
        // Here we skip a full body pre-validation like
        // validation_result = consensus_engine_->pre_validate_block_body(block, chain_state_);
        // because we assume that the sync (BlockExchange) has already checked transaction & ommers root hash
        validation_result = consensus_engine_->pre_validate_transactions(block);
        if (validation_result == ValidationResult::kOk)
            validation_result = consensus_engine_->validate_ommers(block, chain_state_);
    }
    // There is no need to validate a body if its header is on the chain of the pre-verified hashes.
    // Note that here we expect:
    //    1) only bodies on the canonical chain
    //    2) only bodies whose ommers hashes and transaction root hashes were checked against those
    //       of the headers by the sync (BlockExchange)

    if (validation_result != ValidationResult::kOk) {
        unwind_needed_ = true;
        unwind_point_ = block_num - 1;
        bad_block_ = block_hash;
        return;
    }

    if (block_num > highest_height_) {
        highest_height_ = block_num;
    }
}

void BodiesStage::BodyDataModel::close() {
    // does nothing
}

void BodiesStage::BodyDataModel::remove_bodies(BlockNum, std::optional<Hash>, db::RWTxn&) {
    // we do not erase "wrong" blocks, only stage progress will be updated by bodies stage unwind operation
}

BodiesStage::BodiesStage(NodeSettings* ns, SyncContext* sc)
    : Stage(sc, db::stages::kBlockBodiesKey, ns) {
}

Stage::Result BodiesStage::forward(db::RWTxn& tx) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    operation_ = OperationType::Forward;

    try {
        current_height_ = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);
        BlockNum target_height = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);

        BodyDataModel body_persistence(tx, current_height_, node_settings_->chain_config.value());
        body_persistence.set_preverified_height(PreverifiedHashes::current.height);

        get_log_progress();  // this is a trick to set log progress initial value, please improve
        RepeatedMeasure<BlockNum> height_progress(current_height_);

        // block processing
        while (current_height_ < target_height && !body_persistence.unwind_needed() && !is_stopping()) {
            current_height_++;

            // process header and ommers at current height
            Block block;
            bool present = read_canonical_block(tx, current_height_, block);
            if (!present) throw std::logic_error("table Bodies has a hole");

            body_persistence.update_tables(block);

            height_progress.set(body_persistence.highest_height());
        }

        db::stages::write_stage_progress(tx, db::stages::kBlockBodiesKey, current_height_);
        result = Stage::Result::kSuccess;

        // check unwind condition
        if (body_persistence.unwind_needed()) {
            result = Stage::Result::kInvalidBlock;
            sync_context_->unwind_point = body_persistence.unwind_point();
            sync_context_->bad_block_hash = body_persistence.bad_block();
            log::Info(log_prefix_) << "Unwind needed";
        }

        body_persistence.close();

        tx.commit();  // this will commit if the tx was started here

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Forward aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return result;
}

Stage::Result BodiesStage::unwind(db::RWTxn& tx) {
    current_height_ = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    if (!sync_context_->unwind_point.has_value()) return Stage::Result::kSuccess;

    auto new_height = sync_context_->unwind_point.value();
    if (current_height_ <= new_height) return Stage::Result::kSuccess;

    Stage::Result result{Stage::Result::kSuccess};
    operation_ = OperationType::Unwind;

    try {
        BodyDataModel::remove_bodies(new_height, sync_context_->bad_block_hash, tx);
        db::stages::write_stage_progress(tx, db::stages::kBlockBodiesKey, new_height);

        current_height_ = new_height;

        tx.commit();

        result = Stage::Result::kSuccess;

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return result;
}

auto BodiesStage::prune(db::RWTxn&) -> Stage::Result {
    return Stage::Result::kSuccess;
}

std::vector<std::string> BodiesStage::get_log_progress() {  // implementation MUST be thread safe
    static RepeatedMeasure<BlockNum> height_progress{0};

    height_progress.set(current_height_);

    return {"current number", std::to_string(height_progress.get()),
            "progress", std::to_string(height_progress.delta()),
            "bodies/secs", std::to_string(height_progress.throughput())};
}

}  // namespace silkworm::stagedsync
