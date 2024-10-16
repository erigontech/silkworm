/*
   Copyright 2022 The Silkworm Authors

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

#include <memory>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry::rlpx::framing {

class FramingCipherImpl;

class FramingCipher final {
  public:
    struct KeyMaterial {
        Bytes ephemeral_shared_secret;
        bool is_initiator;
        Bytes initiator_nonce;
        Bytes recipient_nonce;
        Bytes initiator_first_message_data;
        Bytes recipient_first_message_data;
    };

    explicit FramingCipher(const KeyMaterial& key_material);
    ~FramingCipher();

    FramingCipher(FramingCipher&&) noexcept;
    FramingCipher& operator=(FramingCipher&&) noexcept;

    Bytes encrypt_frame(Bytes frame_data);

    static size_t header_size();
    size_t decrypt_header(ByteView data);
    static size_t frame_size(size_t header_frame_size);
    Bytes decrypt_frame(ByteView data, size_t header_frame_size);

  private:
    std::unique_ptr<FramingCipherImpl> impl_;
};

}  // namespace silkworm::sentry::rlpx::framing
