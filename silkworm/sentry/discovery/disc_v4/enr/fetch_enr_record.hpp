/*
   Copyright 2023 The Silkworm Authors

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
