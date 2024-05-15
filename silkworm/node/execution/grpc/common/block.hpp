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

#include <string_view>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/types/withdrawal.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>
#include <silkworm/interfaces/types/types.pb.h>

#include "../../api/endpoint/block.hpp"

namespace silkworm::execution::grpc {

void deserialize_hex_as_bytes(std::string_view, std::vector<Bytes>&);

void header_from_proto(const ::execution::Header&, BlockHeader&);
BlockHeader header_from_proto(const ::execution::Header&);
void body_from_proto(const ::execution::BlockBody&, BlockBody&, Hash&, BlockNum&);
api::Body body_from_proto(const ::execution::BlockBody&);

void proto_from_header(const BlockHeader&, ::execution::Header*);
void proto_from_body(const api::Body&, ::execution::BlockBody*);
void proto_from_body(const Block&, ::execution::BlockBody*);
void proto_from_body(const BlockBody&, const Hash&, BlockNum, ::execution::BlockBody*);

void serialize_withdrawal(const Withdrawal&, ::types::Withdrawal*);
Withdrawal withdrawal_from_proto_type(const ::types::Withdrawal&);

}  // namespace silkworm::execution::grpc
