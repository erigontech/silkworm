// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sha3_hasher.hpp"

#include <keccak.h>

#include <silkworm/core/common/util.hpp>

namespace silkworm::sentry::rlpx::crypto {

Sha3Hasher::Sha3Hasher() : impl_(std::make_unique<Keccak>()) {
}

Sha3Hasher::~Sha3Hasher() = default;

void Sha3Hasher::update(ByteView data) {
    impl_->add(data.data(), data.size());
}

Bytes Sha3Hasher::hash() {
    return from_hex(impl_->getHash()).value();
}

}  // namespace silkworm::sentry::rlpx::crypto
