// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
