// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "decoding_exception.hpp"

#include <magic_enum.hpp>

namespace silkworm {

DecodingException::DecodingException(DecodingError err, const std::string& message)
    : std::runtime_error{
          message.empty() ? "Decoding error : " + std::string{magic_enum::enum_name(err)}
                          : message},
      err_{err} {}

}  // namespace silkworm
