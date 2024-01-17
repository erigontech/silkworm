/*
   Copyright 2023 The Silkworm Authors

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
#include <silkworm/core/execution/evm.hpp>

namespace silkworm::protocol::bor {

struct Span {
    uint64_t id{0};
    BlockNum start_block{0};
    BlockNum end_block{0};
};

// See GetCurrentSpan in polygon/bor/spanner.go
std::optional<Span> get_current_span(EVM& evm, const evmc_address& validator_contract);

}  // namespace silkworm::protocol::bor
