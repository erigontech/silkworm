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

#include <silkworm/common/base.hpp>

namespace silkworm::sentry::rlpx::auth {

class EciesCipher {
  public:
    using PublicKey = Bytes;
    using PublicKeyView = ByteView;
    using PrivateKeyView = ByteView;

    struct Message {
        PublicKey ephemeral_public_key;
        Bytes iv;
        Bytes cipher_text;
        Bytes mac;
    };

    static Message encrypt_message(ByteView plain_text, PublicKeyView public_key);
    static Bytes decrypt_message(const Message& message, PrivateKeyView private_key);

    static Bytes encrypt(ByteView plain_text, PublicKeyView public_key);
    static Bytes decrypt(ByteView message_data, PrivateKeyView private_key);

  private:
    static Bytes serialize_message(const Message& message);
    static Message deserialize_message(ByteView message_data);
};

}  // namespace silkworm::sentry::rlpx::auth
