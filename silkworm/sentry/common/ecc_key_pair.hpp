// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "ecc_public_key.hpp"

namespace silkworm::sentry {

class EccKeyPair {
  public:
    EccKeyPair();
    explicit EccKeyPair(Bytes private_key_data);

    EccPublicKey public_key() const;

    ByteView private_key() const { return private_key_; }

    std::string private_key_hex() const;

  private:
    Bytes private_key_;
};

}  // namespace silkworm::sentry
