// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "lookup.hpp"

#include <chrono>

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/parallel_group_utils.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/discovery/disc_v4/ping/ping_check.hpp>

#include "find_neighbors.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

Task<size_t> lookup(
    EccPublicKey local_node_id,
    MessageSender& message_sender,
    boost::signals2::signal<void(NeighborsMessage, EccPublicKey)>& on_neighbors_signal,
    node_db::NodeDb& db) {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    auto now = std::chrono::system_clock::now();
    node_db::NodeDb::FindLookupCandidatesQuery query{
        /* min_pong_time = */ ping::min_valid_pong_time(now),
        /* max_lookup_time = */ now - 10min,
        /* limit = */ 3,
    };
    auto node_ids = co_await db.take_lookup_candidates(query, now);

    size_t total_neighbors = 0;
    auto group_task_factory = [&](size_t index) -> Task<void> {
        const auto& node_id = node_ids[index];
        try {
            total_neighbors += co_await find_neighbors(node_id, local_node_id, message_sender, on_neighbors_signal, db);
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::system::errc::operation_canceled)
                throw;
            SILK_ERROR_M("sentry") << "disc_v4::find::lookup find_neighbors node_id=" << node_id.hex() << " system_error: " << ex.what();
        } catch (const std::exception& ex) {
            SILK_ERROR_M("sentry") << "disc_v4::find::lookup find_neighbors node_id=" << node_id.hex() << " exception: " << ex.what();
        }
    };
    auto group_task = concurrency::generate_parallel_group_task(node_ids.size(), group_task_factory);

    try {
        co_await (std::move(group_task) || concurrency::timeout(1s));
    } catch (const concurrency::TimeoutExpiredError&) {
    }

    co_return total_neighbors;
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
