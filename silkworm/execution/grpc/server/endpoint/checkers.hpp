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
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/checkers.hpp"

namespace silkworm::execution::grpc::server {

::execution::GetHeaderHashNumberResponse response_from_block_num(std::optional<BlockNum>);

::execution::ForkChoice response_from_fork_choice(const api::ForkChoice&);

}  // namespace silkworm::execution::grpc::server
