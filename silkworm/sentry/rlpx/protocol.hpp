// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx {

struct Protocol {
    virtual ~Protocol() = default;
    virtual std::pair<std::string, uint8_t> capability() = 0;
    virtual Message first_message() = 0;
    virtual void handle_peer_first_message(const Message& message) = 0;
    virtual bool is_compatible_enr_entry(std::string_view name, ByteView data) = 0;

    class IncompatiblePeerError : public std::runtime_error {
      public:
        IncompatiblePeerError() : std::runtime_error("rlpx::Protocol: incompatible peer") {}
    };
};

}  // namespace silkworm::sentry::rlpx
