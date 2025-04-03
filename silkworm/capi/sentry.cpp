// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <exception>
#include <latch>
#include <stdexcept>
#include <string_view>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/sentry/sentry.hpp>
#include <silkworm/sentry/settings.hpp>

#include "instance.hpp"
#include "silkworm.h"

using namespace silkworm;
using namespace silkworm::sentry;
using silkworm::concurrency::ContextPoolSettings;

static std::vector<EnodeUrl> parse_peer_urls(const char (&c_urls)[SILKWORM_SENTRY_SETTINGS_PEERS_MAX][200]) {
    std::vector<EnodeUrl> urls;
    for (const auto& c_url : c_urls) {
        std::string_view url_str = c_url;
        if (url_str.empty()) break;
        urls.emplace_back(url_str);
    }
    return urls;
}

static nat::NatOption parse_nat_option(const char (&c_nat)[50]) {
    nat::NatOption nat;
    std::string_view nat_str{c_nat};
    if (!nat_str.empty()) {
        bool ok = nat::lexical_cast(nat_str, nat);
        if (!ok) {
            throw std::runtime_error("make_settings: bad settings.nat string");
        }
    }
    return nat;
}

static Settings make_settings(
    const struct SilkwormSentrySettings& settings,
    ContextPoolSettings context_pool_settings,
    std::filesystem::path data_dir_path) {
    std::string api_address = "127.0.0.1:" + std::to_string(settings.api_port);

    return Settings{
        settings.client_id,
        {},  // log_settings are not used
        api_address,
        settings.port,
        parse_nat_option(settings.nat),
        context_pool_settings,
        std::move(data_dir_path),
        settings.network_id,
        {{Bytes{settings.node_key}}},
        parse_peer_urls(settings.static_peers),
        parse_peer_urls(settings.bootnodes),
        settings.no_discover,
        settings.max_peers,
    };
}

static void log_exception(const std::exception_ptr& ex_ptr, const char* message) {
    try {
        if (ex_ptr) {
            std::rethrow_exception(ex_ptr);
        }
    } catch (const boost::system::system_error& ex) {
        if (ex.code() != boost::system::errc::operation_canceled) {
            SILK_ERROR_M("sentry") << message << " system_error: " << ex.what();
        }
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << message << " exception: " << ex.what();
    } catch (...) {
        SILK_ERROR_M("sentry") << message << " unexpected exception";
    }
}

static void sentry_run(
    Settings settings,
    const boost::asio::cancellation_slot& sentry_stop_signal_slot,
    std::latch& sentry_started);

SILKWORM_EXPORT int silkworm_sentry_start(SilkwormHandle handle, const struct SilkwormSentrySettings* c_settings) SILKWORM_NOEXCEPT {
    try {
        if (!handle) {
            return SILKWORM_INVALID_HANDLE;
        }
        if (!c_settings) {
            return SILKWORM_INVALID_SETTINGS;
        }
        if (handle->sentry_thread) {
            return SILKWORM_SERVICE_ALREADY_STARTED;
        }

        auto settings = make_settings(
            *c_settings,
            handle->context_pool_settings,
            handle->data_dir_path);

        std::latch sentry_started{1};
        std::exception_ptr startup_ex_ptr;

        handle->sentry_thread = std::make_unique<std::thread>([settings = std::move(settings),
                                                               &sentry_stop_signal = handle->sentry_stop_signal,
                                                               &sentry_started,
                                                               &startup_ex_ptr]() mutable {
            try {
                log::set_thread_name("sentry-run");
                sentry_run(std::move(settings), sentry_stop_signal.slot(), sentry_started);
            } catch (...) {
                // error after it's started
                if (sentry_started.try_wait()) {
                    log_exception(std::current_exception(), "sentry_thread");
                }
                // error during startup will be rethrown
                else {
                    startup_ex_ptr = std::current_exception();
                    sentry_started.count_down();
                }
            }
        });

        sentry_started.wait();
        if (startup_ex_ptr) {
            std::rethrow_exception(startup_ex_ptr);
        }

        return SILKWORM_OK;
    } catch (...) {
        log_exception(std::current_exception(), __FUNCTION__);
        return SILKWORM_INTERNAL_ERROR;
    }
}

static void sentry_run(
    Settings settings,
    const boost::asio::cancellation_slot& sentry_stop_signal_slot,
    std::latch& sentry_started) {
    rpc::ClientContextPool context_pool{
        settings.context_pool_settings,
    };

    Sentry sentry{std::move(settings), context_pool.as_executor_pool()};

    auto completion = [&context_pool](const std::exception_ptr& ex_ptr) {
        if (ex_ptr) {
            log_exception(ex_ptr, "sentry.run");
        }
        context_pool.stop();
    };

    boost::asio::co_spawn(
        context_pool.any_executor(),
        sentry.run(),
        boost::asio::bind_cancellation_slot(sentry_stop_signal_slot, completion));

    context_pool.start();

    // signal that it's started, it is safe to call silkworm_sentry_stop() at this point
    sentry_started.count_down();

    context_pool.join();
}

SILKWORM_EXPORT int silkworm_sentry_stop(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    try {
        if (!handle) {
            return SILKWORM_INVALID_HANDLE;
        }
        // check if it's already stopped
        if (!handle->sentry_thread) {
            return SILKWORM_OK;
        }

        // stop sentry.run() task
        handle->sentry_stop_signal.emit(boost::asio::cancellation_type::all);

        handle->sentry_thread->join();
        handle->sentry_thread.reset();

        return SILKWORM_OK;
    } catch (...) {
        log_exception(std::current_exception(), __FUNCTION__);
        return SILKWORM_INTERNAL_ERROR;
    }
}
