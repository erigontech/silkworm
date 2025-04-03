// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "eth_version.hpp"

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;

uint8_t eth_version_from_protocol(proto::Protocol protocol) {
    static_assert(proto::Protocol_MIN == proto::Protocol::ETH65);
    return static_cast<uint8_t>(protocol) + 65;
}

proto::Protocol protocol_from_eth_version(uint8_t version) {
    static_assert(proto::Protocol_MIN == proto::Protocol::ETH65);
    return static_cast<proto::Protocol>(version - 65);
}

}  // namespace silkworm::sentry::grpc::interfaces
