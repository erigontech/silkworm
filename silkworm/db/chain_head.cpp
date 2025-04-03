// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_head.hpp"

#include <gsl/util>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db {

using namespace silkworm::datastore::kvdb;

ChainHead read_chain_head(ROTxn& txn) {
    ChainHead chain_head;

    BlockNum head_block_num = db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey);
    chain_head.block_num = head_block_num;

    auto head_hash = db::read_canonical_header_hash(txn, head_block_num);
    if (head_hash) {
        chain_head.hash = head_hash.value();
    } else {
        SILK_WARN_M("db::ChainHead") << "canonical hash at block_num " << std::to_string(head_block_num) << " not found in db";
        return chain_head;
    }

    auto head_total_difficulty = db::read_total_difficulty(txn, head_block_num, *head_hash);
    if (head_total_difficulty) {
        chain_head.total_difficulty = head_total_difficulty.value();
    } else {
        SILK_WARN_M("db::ChainHead") << "total difficulty of canonical hash at block_num " << std::to_string(head_block_num) << " not found in db";
    }

    return chain_head;
}

ChainHead read_chain_head(datastore::kvdb::ROAccess db_access) {
    auto txn = db_access.start_ro_tx();
    [[maybe_unused]] auto _ = gsl::finally([&txn] { txn.abort(); });

    return read_chain_head(txn);
}

}  // namespace silkworm::db
