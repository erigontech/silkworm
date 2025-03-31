// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "status_manager.hpp"

#include <silkworm/infra/common/log.hpp>

namespace silkworm::sentry {

Task<void> StatusManager::wait_for_status() {
    auto status = co_await status_channel_.receive();
    status_.set(status);
    SILK_DEBUG_M("sentry") << "StatusManager received status: network ID = " << status.message.network_id;
}

Task<void> StatusManager::run() {
    try {
        // loop until wait_for_status() throws a cancelled exception
        while (true) {
            co_await wait_for_status();
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "StatusManager::run unexpected end [operation_canceled]";
        } else {
            SILK_CRIT_M("sentry") << "StatusManager::run unexpected end [" + std::string{se.what()} + "]";
        }
        throw se;
    }
}

}  // namespace silkworm::sentry
