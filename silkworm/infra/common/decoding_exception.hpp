// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>
#include <string>

#include <silkworm/core/common/decoding_result.hpp>

namespace silkworm {

class DecodingException : public std::runtime_error {
  public:
    explicit DecodingException(DecodingError err, const std::string& message = "");

    DecodingError err() const noexcept { return err_; }

  private:
    DecodingError err_;
};

template <class T>
inline void success_or_throw(const tl::expected<T, DecodingError>& res, const std::string& error_message = "") {
    if (!res) {
        throw DecodingException(res.error(), error_message);
    }
}

template <class T>
inline T unwrap_or_throw(tl::expected<T, DecodingError> res, const std::string& error_message = "") {
    success_or_throw(res, error_message);
    return std::move(*res);
}

}  // namespace silkworm
