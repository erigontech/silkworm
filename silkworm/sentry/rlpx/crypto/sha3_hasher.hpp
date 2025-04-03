// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

class Keccak;

namespace silkworm::sentry::rlpx::crypto {

class Sha3Hasher final {
  public:
    Sha3Hasher();
    ~Sha3Hasher();

    void update(ByteView data);
    Bytes hash();

  private:
    std::unique_ptr<Keccak> impl_;
};

}  // namespace silkworm::sentry::rlpx::crypto
