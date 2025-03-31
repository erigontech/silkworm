// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_bodies.hpp"

#include <algorithm>
#include <thread>

#include <magic_enum.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/measure.hpp>

namespace silkworm::stagedsync {

BodiesStage::BodyDataModel::BodyDataModel(
    db::RWTxn& tx,
    db::DataModel data_model,
    BlockNum bodies_stage_block_num,
    const ChainConfig& chain_config)
    : data_model_(data_model),
      chain_config_{chain_config},
      rule_set_{protocol::rule_set_factory(chain_config)},
      chain_state_{tx, std::make_unique<db::BufferFullDataModel>(data_model)},
      initial_block_num_{bodies_stage_block_num},
      max_block_num_{bodies_stage_block_num} {
}

BlockNum BodiesStage::BodyDataModel::initial_block_num() const { return initial_block_num_; }
BlockNum BodiesStage::BodyDataModel::max_block_num() const { return max_block_num_; }
bool BodiesStage::BodyDataModel::unwind_needed() const { return unwind_needed_; }
BlockNum BodiesStage::BodyDataModel::unwind_point() const { return unwind_point_; }
Hash BodiesStage::BodyDataModel::bad_block() const { return bad_block_; }
void BodiesStage::BodyDataModel::set_preverified_block_num(BlockNum block_num) { preverified_block_num_ = block_num; }

// update_tables has the responsibility to update all tables related with the block that is passed as parameter
// Right now there is no table that need to be updated but the name of the method is retained because it makes a pair
// with the same method in the HeadersStages::HeaderDataModel class
void BodiesStage::BodyDataModel::update_tables(const Block& block) {
    Hash block_hash = block.header.hash();  // save cpu
    BlockNum block_num = block.header.number;

    auto validation_result = ValidationResult::kOk;

    // Body validation
    if (block_num > preverified_block_num_) {
        // Here we skip a full body pre-validation like
        // validation_result = rule_set_->pre_validate_block_body(block, chain_state_);
        // because we assume that the sync (BlockExchange) has already checked transaction & ommers root hash
        validation_result = protocol::pre_validate_transactions(block, chain_config_);
        if (validation_result == ValidationResult::kOk) {
            validation_result = rule_set_->validate_ommers(block, chain_state_);
        }
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

    max_block_num_ = std::max(max_block_num_, block_num);
}

void BodiesStage::BodyDataModel::close() {
    // does nothing
}

void BodiesStage::BodyDataModel::remove_bodies(BlockNum, std::optional<Hash>, db::RWTxn&) {
    // we do not erase "wrong" blocks, only stage progress will be updated by bodies stage unwind operation
    // maybe we should remove only the bad block
}

bool BodiesStage::BodyDataModel::get_canonical_block(BlockNum block_num, Block& block) const {
    return data_model_.read_canonical_block(block_num, block);
}

BodiesStage::BodiesStage(
    SyncContext* sync_context,
    const ChainConfig& chain_config,
    db::DataModelFactory data_model_factory,
    std::function<BlockNum()> last_pre_validated_block)
    : Stage(sync_context, db::stages::kBlockBodiesKey),
      chain_config_(chain_config),
      data_model_factory_(std::move(data_model_factory)),
      last_pre_validated_block_(std::move(last_pre_validated_block)) {}

Stage::Result BodiesStage::forward(db::RWTxn& tx) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    operation_ = OperationType::kForward;

    try {
        current_block_num_ = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);
        BlockNum target_block_num = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);

        if (current_block_num_ == target_block_num) {
            // Nothing to process
            return Stage::Result::kSuccess;
        }
        if (current_block_num_ > target_block_num) {
            // Something bad had happened. Maybe we need to unwind ?
            throw StageError(Stage::Result::kInvalidProgress,
                             "Previous progress " + std::to_string(current_block_num_) +
                                 " > target progress " + std::to_string(target_block_num));
        }
        const BlockNum segment_width{target_block_num - current_block_num_};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(current_block_num_),
                       "to", std::to_string(target_block_num),
                       "span", std::to_string(target_block_num - current_block_num_)});
        }
        BodyDataModel body_persistence{
            tx,
            data_model_factory_(tx),
            current_block_num_,
            chain_config_,
        };
        body_persistence.set_preverified_block_num(last_pre_validated_block_());

        get_log_progress();  // this is a trick to set log progress initial value, please improve
        RepeatedMeasure<BlockNum> block_num_progress(current_block_num_);

        // block processing
        while (current_block_num_ < target_block_num && !body_persistence.unwind_needed() && !is_stopping()) {
            ++current_block_num_;

            // process header and ommers at current block_num
            Block block;
            bool present = body_persistence.get_canonical_block(current_block_num_, block);
            if (!present) throw std::logic_error("table Bodies has a hole");

            body_persistence.update_tables(block);

            block_num_progress.set(body_persistence.max_block_num());
        }

        db::stages::write_stage_progress(tx, db::stages::kBlockBodiesKey, current_block_num_);
        result = Stage::Result::kSuccess;

        // check unwind condition
        if (body_persistence.unwind_needed()) {
            result = Stage::Result::kInvalidBlock;
            sync_context_->unwind_point = body_persistence.unwind_point();
            sync_context_->bad_block_hash = body_persistence.bad_block();
            log::Info(log_prefix_) << "Unwind needed";
        }

        body_persistence.close();

        tx.commit_and_renew();

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Forward aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return result;
}

Stage::Result BodiesStage::unwind(db::RWTxn& tx) {
    current_block_num_ = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    if (!sync_context_->unwind_point.has_value()) return Stage::Result::kSuccess;

    auto new_block_num = sync_context_->unwind_point.value();
    if (current_block_num_ <= new_block_num) return Stage::Result::kSuccess;

    operation_ = OperationType::kUnwind;

    const BlockNum segment_width{current_block_num_ - new_block_num};
    if (segment_width > db::stages::kSmallBlockSegmentWidth) {
        log::Info(log_prefix_,
                  {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                   "from", std::to_string(current_block_num_),
                   "to", std::to_string(new_block_num),
                   "span", std::to_string(segment_width)});
    }

    Stage::Result result{Stage::Result::kSuccess};

    try {
        BodyDataModel::remove_bodies(new_block_num, sync_context_->bad_block_hash, tx);
        db::stages::write_stage_progress(tx, db::stages::kBlockBodiesKey, new_block_num);

        current_block_num_ = new_block_num;

        tx.commit_and_renew();

        result = Stage::Result::kSuccess;

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return result;
}

Stage::Result BodiesStage::prune(db::RWTxn&) {
    return Stage::Result::kSuccess;
}

std::vector<std::string> BodiesStage::get_log_progress() {  // implementation MUST be thread safe
    if (!is_stopping()) {
        static RepeatedMeasure<BlockNum> block_num_progress{0};

        block_num_progress.set(current_block_num_);

        return {"current block", std::to_string(block_num_progress.get()),
                "progress", std::to_string(block_num_progress.delta()),
                "bodies/secs", std::to_string(block_num_progress.throughput())};
    }
    return {};
}

}  // namespace silkworm::stagedsync
