// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::enr {

struct EnrRecord {
    EccPublicKey public_key;
    uint64_t seq_num;
    std::optional<NodeAddress> address_v4;
    std::optional<NodeAddress> address_v6;
    std::optional<Bytes> eth1_fork_id_data;
    std::optional<Bytes> eth2_fork_id_data;
    std::optional<Bytes> eth2_attestation_subnets_data;
};

}  // namespace silkworm::sentry::discovery::enr
