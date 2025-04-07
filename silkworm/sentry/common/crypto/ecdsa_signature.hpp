// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::crypto::ecdsa_signature {

Bytes sign_recoverable(ByteView data_hash, ByteView private_key);
EccPublicKey verify_and_recover(ByteView data_hash, ByteView signature_and_recovery_id);

Bytes sign(ByteView data_hash, ByteView private_key);
bool verify(ByteView data_hash, ByteView signature_data, const EccPublicKey& public_key);

}  // namespace silkworm::sentry::crypto::ecdsa_signature
