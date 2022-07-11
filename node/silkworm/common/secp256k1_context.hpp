/*
Copyright 2020-2022 The Silkworm Authors

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

#include <secp256k1.h>
#include <gsl/pointers>

namespace silkworm::sentry {

class SecP256K1Context final {
  public:
    explicit SecP256K1Context(bool allow_verify = true, bool allow_sign = false)
        : context_(secp256k1_context_create(SecP256K1Context::flags(allow_verify, allow_sign))) {}

    ~SecP256K1Context() {
        secp256k1_context_destroy(context_);
    }

    SecP256K1Context(const SecP256K1Context&) = delete;
    SecP256K1Context& operator=(const SecP256K1Context&) = delete;

    // escape hatch
    secp256k1_context* raw() { return context_; }

    bool verify_private_key_data(const ByteView& data) {
        return secp256k1_ec_seckey_verify(context_, data.data());
    }

  private:
    static unsigned int flags(bool allow_verify, bool allow_sign) {
        unsigned int value = SECP256K1_CONTEXT_NONE;
        if (allow_verify) {
            value |= SECP256K1_CONTEXT_VERIFY;
        }
        if (allow_sign) {
            value |= SECP256K1_CONTEXT_SIGN;
        }
        return value;
    }

    gsl::owner<secp256k1_context*> context_;
};

}  // namespace silkworm::sentry
