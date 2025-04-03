// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
