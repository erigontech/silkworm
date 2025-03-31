// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <string>
#include <utility>

#include <silkworm/sentry/rlpx/protocol.hpp>

#include "fork_id.hpp"
#include "status_data.hpp"

namespace silkworm::sentry::eth {

class Protocol : public rlpx::Protocol {
  public:
    explicit Protocol(std::function<StatusData()> status_provider)
        : status_provider_(std::move(status_provider)) {}

    ~Protocol() override = default;

    std::pair<std::string, uint8_t> capability() override {
        return {"eth", Protocol::kVersion};
    }

    Message first_message() override {
        auto status = status_provider_();
        return status.message.to_message();
    }

    void handle_peer_first_message(const Message& message) override;
    bool is_compatible_enr_entry(std::string_view name, ByteView data) override;

    static constexpr uint8_t kVersion{68};

  private:
    std::function<StatusData()> status_provider_;

    static bool is_compatible_fork_id(const ForkId& fork_id, const StatusData& my_status);
};

}  // namespace silkworm::sentry::eth
