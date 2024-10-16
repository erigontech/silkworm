/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/sentry/common/error.hpp>

#include "ecies_cipher_error.hpp"

namespace silkworm::sentry::rlpx::auth {

enum class AuthMessageErrorCode : uint8_t {
    kDecryptFailure = 1,
    kBadRLP,
};

enum class AuthMessageType : uint8_t {
    kAuth = 1,
    kAuthAck,
};

class AuthMessageErrorBase : public sentry::Error<AuthMessageErrorCode> {
  public:
    AuthMessageErrorBase(AuthMessageType message_type, AuthMessageErrorCode code)
        : sentry::Error<AuthMessageErrorCode>(code, ""),
          message_type_(message_type) {}

    AuthMessageType message_type() const { return message_type_; }

  private:
    AuthMessageType message_type_;
};

class AuthMessageErrorDecryptFailure : public AuthMessageErrorBase, private EciesCipherError {
  public:
    explicit AuthMessageErrorDecryptFailure(
        AuthMessageType message_type,
        Bytes message_data,
        const EciesCipherError& cause)
        : AuthMessageErrorBase(message_type, AuthMessageErrorCode::kDecryptFailure),
          EciesCipherError(cause),
          message_data_(std::move(message_data)) {}

    EciesCipherErrorCode cause_code() const { return EciesCipherError::code(); }
    const char* what() const noexcept override { return EciesCipherError::what(); }
    ByteView message_data() const { return message_data_; }

  private:
    Bytes message_data_;
};

class AuthMessageErrorBadRLP : public AuthMessageErrorBase, private DecodingException {
  public:
    explicit AuthMessageErrorBadRLP(
        AuthMessageType message_type,
        DecodingError cause)
        : AuthMessageErrorBase(message_type, AuthMessageErrorCode::kBadRLP),
          DecodingException(cause) {}

    DecodingError cause_code() const { return err(); }
    const char* what() const noexcept override { return DecodingException::what(); }
};

}  // namespace silkworm::sentry::rlpx::auth
