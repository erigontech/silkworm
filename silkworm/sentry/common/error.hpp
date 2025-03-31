// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>

namespace silkworm::sentry {

template <typename TErrorCode>
class Error : public std::runtime_error {
  public:
    Error(TErrorCode code, const char* message)
        : std::runtime_error(message),
          code_(code) {}
    TErrorCode code() const { return code_; }

  private:
    TErrorCode code_;
};

}  // namespace silkworm::sentry
