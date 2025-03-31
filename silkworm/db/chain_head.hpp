// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/types/chain_head.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::db {

ChainHead read_chain_head(datastore::kvdb::ROTxn& txn);
ChainHead read_chain_head(datastore::kvdb::ROAccess db_access);

}  // namespace silkworm::db
