// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "async_thread.hpp"

#include <thread>

#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <boost/thread.hpp>

#include <silkworm/infra/common/log.hpp>

#include "event_notifier.hpp"

namespace silkworm::concurrency {

Task<void> async_thread(
    std::function<void()> run,
    std::function<void()> stop,
    const char* name,
    std::optional<size_t> stack_size) {
    std::exception_ptr run_exception;

    auto executor = co_await boost::asio::this_coro::executor;
    EventNotifier thread_finished_notifier{executor};

    boost::thread::attributes attributes;
    if (stack_size) {
        attributes.set_stack_size(*stack_size);
    }

    boost::thread thread{attributes, [run = std::move(run), name = name, &run_exception, &thread_finished_notifier] {
                             log::set_thread_name(name);
                             try {
                                 SILK_TRACE << "Async thread [" << name << "] run started";
                                 run();
                                 SILK_TRACE << "Async thread [" << name << "] run completed";
                             } catch (...) {
                                 run_exception = std::current_exception();
                             }

                             try {
                                 thread_finished_notifier.notify();
                             } catch (const std::exception& ex) {
                                 SILK_ERROR << "async_thread thread_finished_notifier.notify exception: " << ex.what();
                             }
                         }};

    try {
        co_await thread_finished_notifier.wait();
        thread.join();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            try {
                stop();
            } catch (const std::exception& stop_ex) {
                SILK_ERROR << "async_thread stop exception: " << stop_ex.what();
                throw;
            }
            thread.join();
        } else {
            SILK_ERROR << "async_thread thread_finished_notifier.wait system_error: " << ex.what();
            throw;
        }
    } catch (...) {
        SILK_CRIT << "async_thread thread_finished_notifier.wait unexpected exception";
        throw;
    }

    if (run_exception) {
        std::rethrow_exception(run_exception);
    }
}

}  // namespace silkworm::concurrency
