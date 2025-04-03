// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::db {

//! \brief Validates provided genesis json payload
//! \param [in] genesis_json : the payload to validate
//! \returns A pair of bool and a vector of string errors (if any)
std::pair<bool, std::vector<std::string>> validate_genesis_json(const nlohmann::json& genesis_json);

//! \brief Initializes database with genesis account allocation only from JSON payload
//! \param [in] txn : a RW MDBX transaction
//! \param [in] genesis_json : the genesis JSON payload
//! \returns the state root hash after account allocation
evmc::bytes32 initialize_genesis_allocations(RWTxn& txn, const nlohmann::json& genesis_json);

void write_genesis_allocation_to_db(RWTxn& txn, const InMemoryState& genesis_allocation);

//! \brief Initializes database with genesis from JSON payload
//! \param [in] txn : a RW MDBX transaction
//! \param [in] genesis_json : the genesis JSON payload
//! \param [in] allow_exceptions : whether to throw exceptions on failure(s)
//! \returns True/False
bool initialize_genesis(RWTxn& txn, const nlohmann::json& genesis_json, bool allow_exceptions);

}  // namespace silkworm::db
