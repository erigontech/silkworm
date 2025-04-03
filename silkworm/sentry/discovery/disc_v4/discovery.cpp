// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "discovery.hpp"

#include <boost/asio/this_coro.hpp>
#include <boost/signals2.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <gsl/util>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/concurrency/task_group.hpp>

#include "enr/enr_request_handler.hpp"
#include "enr/fetch_enr_record.hpp"
#include "find/find_node_handler.hpp"
#include "find/lookup.hpp"
#include "message_handler.hpp"
#include "ping/ping_check.hpp"
#include "ping/ping_handler.hpp"
#include "server.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

class DiscoveryImpl : private MessageHandler {
  public:
    DiscoveryImpl(
        const boost::asio::any_io_executor& executor,
        uint16_t server_port,
        std::function<EccKeyPair()> node_key,  // NOLINT(performance-unnecessary-value-param)
        std::function<EnodeUrl()> node_url,
        std::function<discovery::enr::EnrRecord()> node_record,
        node_db::NodeDb& node_db)
        : node_id_([node_key]() { return node_key().public_key(); }),
          node_url_(std::move(node_url)),
          node_record_(std::move(node_record)),
          node_db_(node_db),
          server_(executor, server_port, node_key, *this),
          ping_checks_semaphore_(executor, kPingChecksTasksMax),
          ping_checks_tasks_(executor, kPingChecksTasksMax),
          discovered_event_notifier_(executor),
          discover_more_needed_notifier_(executor) {}
    ~DiscoveryImpl() override = default;

    DiscoveryImpl(const DiscoveryImpl&) = delete;
    DiscoveryImpl& operator=(const DiscoveryImpl&) = delete;

    Task<void> run() {
        using namespace concurrency::awaitable_wait_for_all;
        server_.setup();
        try {
            co_await (server_.run() && discover_more() && ping_checks() && ping_checks_tasks_.wait());
        } catch (const boost::system::system_error& ex) {
            SILK_ERROR_M("sentry") << "DiscoveryImpl::run ex=" << ex.what();
            if (ex.code() == boost::system::errc::operation_canceled) {
                // TODO(canepat) demote to debug after https://github.com/erigontech/silkworm/issues/2333 is solved
                SILK_WARN_M("sentry") << "DiscoveryImpl::run operation_canceled";
            }
            throw;
        }
    }

    void discover_more_needed() {
        discover_more_needed_notifier_.notify();
    }

  private:
    uint64_t local_enr_seq_num() const {
        return this->node_record_().seq_num;
    }

    Task<void> on_find_node(find::FindNodeMessage message, EccPublicKey sender_public_key, boost::asio::ip::udp::endpoint sender_endpoint) override {
        return find::FindNodeHandler::handle(std::move(message), std::move(sender_public_key), std::move(sender_endpoint), server_, node_db_);
    }

    Task<void> on_neighbors(find::NeighborsMessage message, EccPublicKey sender_public_key) override {
        on_neighbors_signal_(std::move(message), std::move(sender_public_key));
        co_return;
    }

    Task<void> on_ping(ping::PingMessage message, EccPublicKey sender_public_key, boost::asio::ip::udp::endpoint sender_endpoint, Bytes ping_packet_hash) override {
        bool is_new = co_await ping::PingHandler::handle(
            std::move(message),
            std::move(sender_public_key),
            std::move(sender_endpoint),
            std::move(ping_packet_hash),
            node_id_(),
            local_enr_seq_num(),
            server_,
            node_db_);
        if (is_new) {
            discovered_event_notifier_.notify();
        }
    }

    Task<void> on_pong(ping::PongMessage message, EccPublicKey sender_public_key) override {
        on_pong_signal_(std::move(message), std::move(sender_public_key));
        co_return;
    }

    Task<void> on_enr_request(enr::EnrRequestMessage message, EccPublicKey sender_public_key, boost::asio::ip::udp::endpoint sender_endpoint, Bytes packet_hash) override {
        return enr::EnrRequestHandler::handle(
            message,
            std::move(sender_public_key),
            std::move(sender_endpoint),
            std::move(packet_hash),
            node_record_(),
            server_,
            node_db_);
    }

    Task<void> on_enr_response(enr::EnrResponseMessage message) override {
        on_enr_response_signal_(std::move(message));
        co_return;
    }

    Task<void> discover_more() {
        using namespace std::chrono_literals;

        while (true) {
            co_await discover_more_needed_notifier_.wait();

            auto total_neighbors = co_await find::lookup(node_id_(), server_, on_neighbors_signal_, node_db_);

            if (total_neighbors == 0) {
                co_await sleep(10s);
                discover_more_needed_notifier_.notify();
            } else {
                discovered_event_notifier_.notify();
            }
        }
    }

    Task<void> ping_checks() {
        using namespace std::chrono_literals;
        using namespace concurrency::awaitable_wait_for_one;
        auto executor = co_await boost::asio::this_coro::executor;

        while (true) {
            auto now = std::chrono::system_clock::now();
            auto node_ids = co_await node_db_.find_ping_candidates(now, 10);
            if (node_ids.empty()) {
                co_await (sleep(10s) || discovered_event_notifier_.wait());
                continue;
            }

            for (auto& node_id : node_ids) {
                // grab the semaphore and block once we reach kPingChecksTasksMax
                co_await ping_checks_semaphore_.send(node_id.serialized());
                ping_checks_tasks_.spawn(executor, [this, node_id = std::move(node_id)]() mutable -> Task<void> {
                    // when a ping check is going to finish, unblock the semaphore
                    [[maybe_unused]] auto _ = gsl::finally([this] {
                        auto finished_task_id = this->ping_checks_semaphore_.try_receive();
                        SILKWORM_ASSERT(finished_task_id.has_value());
                    });
                    co_await this->ping_check(std::move(node_id));
                }());
            }
        }
    }

    Task<void> ping_check(EccPublicKey node_id) {
        using namespace std::chrono_literals;

        auto local_node_url = node_url_();
        if (node_id == local_node_url.public_key()) {
            SILK_WARN_M("sentry")
                << "disc_v4::DiscoveryImpl::ping_check: "
                << "ignoring an attempt to ping the local node, "
                << "please delete it from the NodeDb by node_id=" << node_id.hex();
            co_return;
        }

        try {
            auto ping_check_result = co_await ping::ping_check(node_id, local_node_url, local_enr_seq_num(), server_, on_pong_signal_, node_db_);
            if (ping_check_result.is_skipped()) {
                co_return;
            }

            if (ping_check_result.is_success()) {
                // wait enough time for "ping back" to happen
                // so that the remote peer verifies us and accepts our ENR request
                co_await sleep(1s);

                auto current_enr_seq_num = co_await node_db_.find_enr_seq_num(node_id);
                if (current_enr_seq_num != ping_check_result.enr_seq_num) {
                    auto address = co_await node_db_.find_node_address(node_id);
                    if (!address) {
                        throw std::runtime_error("ping_check: node address not found");
                    }
                    auto endpoint = address->to_common_address().endpoint;
                    auto enr_record = co_await enr::fetch_enr_record(node_id, std::move(endpoint), server_, on_enr_response_signal_);
                    if (enr_record) {
                        co_await node_db_.update_eth1_fork_id(enr_record->public_key, enr_record->eth1_fork_id_data);
                        co_await node_db_.update_enr_seq_num(enr_record->public_key, enr_record->seq_num);
                    }
                }
            }

            co_await ping_check_result.save(node_db_);

        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::system::errc::operation_canceled)
                throw;
            SILK_ERROR_M("sentry") << "disc_v4::DiscoveryImpl::ping_check node_id=" << node_id.hex() << " system_error: " << ex.what();
        } catch (const std::exception& ex) {
            SILK_ERROR_M("sentry") << "disc_v4::DiscoveryImpl::ping_check node_id=" << node_id.hex() << " exception: " << ex.what();
        }
    }

    std::function<EccPublicKey()> node_id_;
    std::function<EnodeUrl()> node_url_;
    std::function<discovery::enr::EnrRecord()> node_record_;
    node_db::NodeDb& node_db_;
    Server server_;
    concurrency::Channel<Bytes> ping_checks_semaphore_;
    concurrency::TaskGroup ping_checks_tasks_;
    static constexpr size_t kPingChecksTasksMax = 3;
    concurrency::EventNotifier discovered_event_notifier_;
    concurrency::EventNotifier discover_more_needed_notifier_;
    boost::signals2::signal<void(find::NeighborsMessage, EccPublicKey)> on_neighbors_signal_;
    boost::signals2::signal<void(ping::PongMessage, EccPublicKey)> on_pong_signal_;
    boost::signals2::signal<void(enr::EnrResponseMessage)> on_enr_response_signal_;
};

Discovery::Discovery(
    const boost::asio::any_io_executor& executor,
    uint16_t server_port,
    std::function<EccKeyPair()> node_key,
    std::function<EnodeUrl()> node_url,
    std::function<discovery::enr::EnrRecord()> node_record,
    node_db::NodeDb& node_db)
    : p_impl_(std::make_unique<DiscoveryImpl>(executor, server_port, std::move(node_key), std::move(node_url), std::move(node_record), node_db)) {}

Discovery::~Discovery() {
    SILK_TRACE_M("sentry") << "silkworm::sentry::discovery::disc_v4::Discovery::~Discovery";
}

Task<void> Discovery::run() {
    return p_impl_->run();
}

void Discovery::discover_more_needed() {
    p_impl_->discover_more_needed();
}

}  // namespace silkworm::sentry::discovery::disc_v4
