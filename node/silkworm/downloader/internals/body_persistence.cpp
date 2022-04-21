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

#include "body_persistence.hpp"

namespace silkworm {

BodyPersistence::BodyPersistence(Db::ReadWriteAccess::Tx& tx, const ChainIdentity& ci)
    : tx_{tx},
      consensus_engine_{consensus::engine_factory(ci.chain)},
      chain_state_{tx.raw(), /*prune_from=*/0, /*historical_block=null*/} {

    auto bodies_stage_height = tx.read_stage_progress(db::stages::kBlockBodiesKey);

    initial_height_ = bodies_stage_height;
    highest_height_ = bodies_stage_height;
}

BlockNum BodyPersistence::initial_height() const { return initial_height_; }
BlockNum BodyPersistence::highest_height() const { return highest_height_; }
bool BodyPersistence::unwind_needed() const { return unwind_needed_; }
BlockNum BodyPersistence::unwind_point() const { return unwind_point_; }
Hash BodyPersistence::bad_block() const { return bad_block_; }

void BodyPersistence::persist(const Block& block) {
    Hash block_hash = block.header.hash(); // save cpu
    BlockNum block_num = block.header.number;

    // todo: ask! (pre_validate_block() is more strong than Erigon does, but it seems more aligned with the yellow paper)
    auto validation_result = consensus_engine_->pre_validate_block(block, chain_state_);

    if (validation_result != ValidationResult::kOk) {
        unwind_needed_ = true;
        unwind_point_ = block_num - 1;
        bad_block_ = block_hash;
        return;
    }

    if (!tx_.has_body(block_hash, block_num))
        tx_.write_body(block, block_hash, block_num);

    if (block_num > highest_height_)
        highest_height_ = block_num;
}

void BodyPersistence::persist(const std::vector<Block>& blocks) {
    for(auto& block: blocks) {
        persist(block);
    }
}

void BodyPersistence::close() {

}

}
