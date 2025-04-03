// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "session_sentry_client.hpp"

#include <mutex>
#include <optional>
#include <tuple>

#include <silkworm/infra/concurrency/awaitable_condition_variable.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

class SessionSentryClientImpl : public api::SentryClient {
  private:
    enum class State {
        kInit,
        kReconnect,
        kHandshake,
        kSetStatus,
        kReady,
    };

    enum class Event {
        kSessionRequired,
        kTransitioned,
        kDisconnected,
    };

  public:
    using StatusDataProvider = SessionSentryClient::StatusDataProvider;
    using Waiter = concurrency::AwaitableConditionVariable::Waiter;

    SessionSentryClientImpl(
        std::shared_ptr<api::SentryClient> sentry_client,
        StatusDataProvider status_data_provider)
        : sentry_client_(std::move(sentry_client)),
          status_data_provider_(std::move(status_data_provider)) {
        sentry_client_->on_disconnect([this] { return this->handle_disconnect(); });
    }

    ~SessionSentryClientImpl() override {
        sentry_client_->on_disconnect([]() -> Task<void> { co_return; });
    }

    Task<std::shared_ptr<api::Service>> service() override {
        co_await run_transitions_until_ready(Event::kSessionRequired);
        co_return (co_await sentry_client_->service());
    }

    bool is_ready() override {
        std::scoped_lock lock(state_mutex_);
        return (state_ == State::kReady) || (state_ == State::kInit);
    }

    void on_disconnect(std::function<Task<void>()> /*callback*/) override {
        SILKWORM_ASSERT(false);
    }

    Task<void> reconnect() override {
        co_await run_transitions_until_ready(Event::kSessionRequired);
    }

  private:
    static State next_state(State state, Event event) {
        if (event == Event::kDisconnected) {
            return State::kReconnect;
        }
        if ((event == Event::kSessionRequired) && (state != State::kInit)) {
            return state;
        }
        // Event::kTransitioned or State::kInit
        switch (state) {
            case State::kInit:
            case State::kReconnect:
                return State::kHandshake;
            case State::kHandshake:
                return State::kSetStatus;
            case State::kSetStatus:
            case State::kReady:
                return State::kReady;
        }
        SILKWORM_ASSERT(false);
        return state;
    }

    std::tuple<State, std::optional<Waiter>> proceed_to_next_state(Event event) {
        std::scoped_lock lock(state_mutex_);
        State old_state = state_;
        State new_state = next_state(old_state, event);
        state_ = new_state;

        // if the state didn't change, we might need to wait
        std::optional<Waiter> ready_waiter;
        if (new_state == old_state) {
            ready_waiter = ready_cond_var_.waiter();
        }

        return {new_state, std::move(ready_waiter)};
    }

    Task<void> transition_to_state(State new_state) {
        using namespace std::chrono_literals;

        switch (new_state) {
            case State::kInit:
                SILKWORM_ASSERT(false);
                break;
            case State::kReconnect: {
                // Delay reconnection to make these corner cases less likely:
                // - a late failed call triggers Event::kDisconnected again, and we'll have to redo the handshake;
                // - a successful reconnect right after co_await service() where a call would proceed without a handshake;
                co_await sleep(1s);
                co_await sentry_client_->reconnect();
                break;
            }
            case State::kHandshake: {
                auto service = co_await sentry_client_->service();
                eth_version_ = co_await service->handshake();
                break;
            }
            case State::kSetStatus: {
                auto status_data = co_await status_data_provider_(eth_version_);
                auto service = co_await sentry_client_->service();
                co_await service->set_status(std::move(status_data));
                break;
            }
            case State::kReady: {
                std::scoped_lock lock(state_mutex_);
                ready_cond_var_.notify_all();
                break;
            }
        }
    }

    Task<void> run_transitions_until_ready(Event event) {
        State state{State::kInit};
        std::optional<Waiter> ready_waiter;
        do {
            std::tie(state, ready_waiter) = proceed_to_next_state(event);
            if (!ready_waiter) {
                co_await transition_to_state(state);
                event = Event::kTransitioned;
            } else if (state != State::kReady) {
                co_await ready_waiter.value()();
                event = Event::kSessionRequired;
            }
        } while (state != State::kReady);
    }

    Task<void> handle_disconnect() {
        return run_transitions_until_ready(Event::kDisconnected);
    }

    std::shared_ptr<api::SentryClient> sentry_client_;
    StatusDataProvider status_data_provider_;
    uint8_t eth_version_{0};
    State state_{State::kInit};
    std::mutex state_mutex_;
    concurrency::AwaitableConditionVariable ready_cond_var_;
};

SessionSentryClient::SessionSentryClient(
    std::shared_ptr<api::SentryClient> sentry_client,
    StatusDataProvider status_data_provider)
    : p_impl_(std::make_unique<SessionSentryClientImpl>(std::move(sentry_client), std::move(status_data_provider))) {
}

SessionSentryClient::~SessionSentryClient() {
    [[maybe_unused]] int non_trivial_destructor{0};  // silent clang-tidy
}

Task<std::shared_ptr<api::Service>> SessionSentryClient::service() {
    return p_impl_->service();
}

bool SessionSentryClient::is_ready() {
    return p_impl_->is_ready();
}

void SessionSentryClient::on_disconnect(std::function<Task<void>()> callback) {
    p_impl_->on_disconnect(callback);
}

Task<void> SessionSentryClient::reconnect() {
    return p_impl_->reconnect();
}

}  // namespace silkworm::sentry
