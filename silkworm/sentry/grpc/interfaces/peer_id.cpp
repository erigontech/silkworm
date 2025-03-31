// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "peer_id.hpp"

#include <silkworm/infra/grpc/common/conversion.hpp>

namespace silkworm::sentry::grpc::interfaces {

namespace proto_types = ::types;
using namespace silkworm::rpc;

sentry::EccPublicKey peer_public_key_from_id(const ::types::H512& peer_id) {
    return sentry::EccPublicKey::deserialize(bytes_from_h512(peer_id));
}

proto_types::H512 peer_id_from_public_key(const sentry::EccPublicKey& key) {
    return *h512_from_bytes(key.serialized());
}

std::string peer_id_string_from_public_key(const sentry::EccPublicKey& key) {
    return key.hex();
}

}  // namespace silkworm::sentry::grpc::interfaces
