// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::grpc::interfaces {

sentry::EccPublicKey peer_public_key_from_id(const ::types::H512& peer_id);
::types::H512 peer_id_from_public_key(const sentry::EccPublicKey& key);

std::string peer_id_string_from_public_key(const sentry::EccPublicKey& key);

}  // namespace silkworm::sentry::grpc::interfaces
