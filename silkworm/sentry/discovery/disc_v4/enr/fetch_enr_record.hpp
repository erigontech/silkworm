// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>
#include <boost/signals2.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>

#include "enr_response_message.hpp"
#include "message_sender.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

Task<std::optional<discovery::enr::EnrRecord>> fetch_enr_record(
    EccPublicKey node_id,
    boost::asio::ip::udp::endpoint endpoint,
    MessageSender& message_sender,
    boost::signals2::signal<void(EnrResponseMessage)>& on_enr_response_signal);

}  // namespace silkworm::sentry::discovery::disc_v4::enr
