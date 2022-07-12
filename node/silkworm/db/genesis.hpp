/*
    Copyright 2021 The Silkworm Authors

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

#pragma once
#ifndef SILKWORM_DB_GENESIS_HPP_
#define SILKWORM_DB_GENESIS_HPP_

#include "access_layer.hpp"

namespace silkworm::db {
//! \brief Validates provided genesis json payload
//! \param [in] genesis_json : the payload to validate
//! \returns A pair of bool and a vector of string errors (if any)
std::pair<bool, std::vector<std::string>> validate_genesis_json(const nlohmann::json& genesis_json);

//! \brief Initializes database with genesis from json payload
//! \param [in] txn : a RW MDBX transaction
//! \param [in] genesis_json : the payload to write
//! \param [in] allow_exceptions : whether to throw exceptions on failure(s)
//! \returns True/False
bool initialize_genesis(mdbx::txn& txn, const nlohmann::json& genesis_json, bool allow_exceptions);

}  // namespace silkworm::db

#endif  // SILKWORM_DB_GENESIS_HPP_
