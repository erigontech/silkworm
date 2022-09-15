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

#include "body_persistence.hpp"

#include <silkworm/db/stages.hpp>

namespace silkworm {

BodyPersistence::BodyPersistence(db::RWTxn& tx, const ChainConfig& chain_config)
    : tx_{tx},
      consensus_engine_{consensus::engine_factory(chain_config)},
      chain_state_{tx, /*prune_from=*/0, /*historical_block=null*/} {
    auto bodies_stage_height = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);

    initial_height_ = bodies_stage_height;
    highest_height_ = bodies_stage_height;
}

BlockNum BodyPersistence::initial_height() const { return initial_height_; }
BlockNum BodyPersistence::highest_height() const { return highest_height_; }
bool BodyPersistence::unwind_needed() const { return unwind_needed_; }
BlockNum BodyPersistence::unwind_point() const { return unwind_point_; }
Hash BodyPersistence::bad_block() const { return bad_block_; }
void BodyPersistence::set_preverified_height(BlockNum height) { preverified_height_ = height; }

void BodyPersistence::persist(const Block& block) {
    Hash block_hash = block.header.hash();  // save cpu
    BlockNum block_num = block.header.number;

    auto validation_result = ValidationResult::kOk;
    if (block_num > preverified_height_) {
        validation_result = consensus_engine_->validate_ommers(block, chain_state_);
    }
    // there is no need to validate a body if its header is on the chain of the pre-verified hashes;
    // note that here we expect:
    //    1) only bodies on the canonical chain
    //    2) only bodies whose ommers hashes and transaction root hashes were checked against those of the headers

    if (validation_result != ValidationResult::kOk) {
        unwind_needed_ = true;
        unwind_point_ = block_num - 1;
        bad_block_ = block_hash;
        return;
    }

    if (!db::has_body(tx_, block_num, block_hash)) {
        db::write_body(tx_, block, block_hash, block_num);
    }

    if (block_num > highest_height_) {
        highest_height_ = block_num;
        db::stages::write_stage_progress(tx_, db::stages::kBlockBodiesKey, block_num);
    }
}

void BodyPersistence::persist(const std::vector<Block>& blocks) {
    for (auto& block : blocks) {
        persist(block);
    }
}

void BodyPersistence::close() {
    // does nothing
}

void BodyPersistence::remove_bodies(BlockNum new_height, std::optional<Hash>, db::RWTxn& tx) {
    // like Erigon, we do not erase "wrong" blocks, only update stage progress...
    db::stages::write_stage_progress(tx, db::stages::kBlockBodiesKey, new_height);
}

}  // namespace silkworm
