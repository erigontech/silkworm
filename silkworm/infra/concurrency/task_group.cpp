/*
   Copyright 2022 The Silkworm Authors

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

#include "task_group.hpp"

#include <cassert>
#include <tuple>
#include <utility>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::concurrency {

using namespace boost::asio;

void TaskGroup::spawn(any_io_executor&& executor, awaitable<void> task) {
    std::scoped_lock lock(mutex_);

    if (is_closed_) {
        throw SpawnAfterCloseError();
    }

    auto task_id = ++last_task_id_;

    auto [it, ok] = tasks_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(task_id),
        std::forward_as_tuple());
    assert(ok);
    auto cancellation_slot = it->second.slot();

    auto completion = [this, task_id](const std::exception_ptr& ex_ptr) {
        this->on_complete(task_id, ex_ptr);
    };

    co_spawn(executor, std::move(task), bind_cancellation_slot(cancellation_slot, completion));
}

awaitable<void> TaskGroup::wait() {
    // wait until cancelled
    try {
        co_await completions_.receive();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            close();
        } else {
            log::Error() << "TaskGroup::wait system_error: " << ex.what();
            throw;
        }
    }

    co_await this_coro::reset_cancellation_state();

    // wait for all tasks completions
    while (!is_completed()) {
        auto completed_task_id = co_await completions_.receive();
        {
            std::scoped_lock lock(mutex_);
            tasks_.erase(completed_task_id);
        }
    }

    throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
}

void TaskGroup::close() {
    std::scoped_lock lock(mutex_);
    is_closed_ = true;
    for (auto& [task_id, canceller] : tasks_) {
        canceller.emit(cancellation_type::all);
    }
}

void TaskGroup::on_complete(std::size_t task_id, const std::exception_ptr& ex_ptr) {
    // rethrow exception unless it is an expected operation_canceled
    try {
        if (ex_ptr) {
            std::rethrow_exception(ex_ptr);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != boost::system::errc::operation_canceled) {
            log::Error() << "TaskGroup::on_complete system_error: " << e.what();
            throw;
        }
    } catch (const std::exception& e) {
        log::Error() << "TaskGroup::on_complete exception: " << e.what();
        throw;
    }

    std::scoped_lock lock(mutex_);
    if (is_closed_) {
        bool ok = completions_.try_send(task_id);
        if (!ok) {
            throw std::runtime_error("TaskGroup::on_complete: completions queue is full, unexpected max_tasks limit breach");
        }
    } else {
        tasks_.erase(task_id);
    }
}

bool TaskGroup::is_completed() {
    std::scoped_lock lock(mutex_);
    return is_closed_ && tasks_.empty();
}

}  // namespace silkworm::concurrency
