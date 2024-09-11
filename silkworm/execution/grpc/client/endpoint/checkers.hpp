/*
   Copyright 2024 The Silkworm Authors

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

#include <optional>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/checkers.hpp"

namespace silkworm::execution::grpc::client {

::types::H256 h256_from_block_hash(const Hash& block_hash);

std::optional<BlockNum> block_number_from_response(const ::execution::GetHeaderHashNumberResponse&);

api::ForkChoice fork_choice_from_response(const ::execution::ForkChoice&);

}  // namespace silkworm::execution::grpc::client
