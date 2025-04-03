// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <set>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::db {

//! \brief Return (block-num, hash) of the header with the biggest total difficulty skipping bad headers
std::tuple<BlockNum, Hash> header_with_biggest_td(datastore::kvdb::ROTxn& txn, const std::set<Hash>* bad_headers = nullptr);

}  // namespace silkworm::db
