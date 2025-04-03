// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "task_group.hpp"

#include <tuple>
#include <utility>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;

void TaskGroup::spawn(const any_io_executor& executor, Task<void> task) {
    std::scoped_lock lock(mutex_);

    if (is_closed_) {
        throw SpawnAfterCloseError();
    }

    auto task_id = ++last_task_id_;

    auto [it, ok] = tasks_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(task_id),
        std::forward_as_tuple());
    SILKWORM_ASSERT(ok);
    auto cancellation_slot = it->second.slot();

    auto completion = [this, task_id](const std::exception_ptr& ex_ptr) {
        this->on_complete(task_id, ex_ptr);
    };

    co_spawn(executor, std::move(task), bind_cancellation_slot(cancellation_slot, completion));
}

Task<void> TaskGroup::wait() {
    // wait until cancelled or a task throws an exception
    std::exception_ptr ex_ptr;
    try {
        ex_ptr = co_await exceptions_.receive();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            ex_ptr = std::current_exception();
        } else {
            SILK_ERROR << "TaskGroup::wait system_error: " << ex.what();
            throw;
        }
    }

    co_await this_coro::reset_cancellation_state();
    close();

    // wait for all tasks completions
    while (!is_completed()) {
        auto [completed_task_id, result_ex_ptr] = co_await completions_.receive();

        {
            std::scoped_lock lock(mutex_);
            tasks_.erase(completed_task_id);
        }

        if (result_ex_ptr) {
            ex_ptr = result_ex_ptr;
        }
    }

    std::rethrow_exception(ex_ptr);
}

void TaskGroup::close() {
    std::scoped_lock lock(mutex_);
    is_closed_ = true;
    for (auto& [task_id, canceller] : tasks_) {
        canceller.emit(cancellation_type::all);
    }
}

static bool is_operation_cancelled_error(const std::exception_ptr& ex_ptr) {
    try {
        std::rethrow_exception(ex_ptr);
    } catch (const boost::system::system_error& e) {
        return (e.code() == boost::system::errc::operation_canceled);
    } catch (...) {
        return false;
    }
}

void TaskGroup::on_complete(size_t task_id, const std::exception_ptr& ex_ptr) {
    bool is_cancelled = ex_ptr && is_operation_cancelled_error(ex_ptr);

    std::scoped_lock lock(mutex_);
    if (is_closed_) {
        // if a task threw during cancellation - rethrow from wait()
        auto result_ex_ptr = (ex_ptr && !is_cancelled) ? ex_ptr : std::exception_ptr{};

        bool ok = completions_.try_send({task_id, result_ex_ptr});
        if (!ok) {
            throw std::runtime_error("TaskGroup::on_complete: completions queue is full, unexpected max_tasks limit breach");
        }
    } else {
        tasks_.erase(task_id);

        // if a task threw - rethrow from wait()
        if (ex_ptr && !is_cancelled) {
            exceptions_.try_send(ex_ptr);
        }
    }
}

bool TaskGroup::is_completed() {
    std::scoped_lock lock(mutex_);
    return is_closed_ && tasks_.empty();
}

}  // namespace silkworm::concurrency
