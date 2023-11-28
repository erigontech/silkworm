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

#pragma once

#include <atomic>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <ostream>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/concurrency/executor_pool.hpp>
#include <silkworm/infra/concurrency/idle_strategy.hpp>

namespace silkworm::concurrency {

//! Asynchronous scheduler running an execution loop.
class Context {
  public:
    explicit Context(std::size_t context_id, WaitMode wait_mode = WaitMode::blocking);
    virtual ~Context() = default;

    [[nodiscard]] boost::asio::io_context* io_context() const noexcept { return io_context_.get(); }
    [[nodiscard]] WaitMode wait_mode() const noexcept { return wait_mode_; }
    [[nodiscard]] std::size_t id() const noexcept { return context_id_; }

    //! Execute the scheduler loop until stopped.
    virtual void execute_loop();

    //! Stop the execution loop.
    void stop();

  protected:
    //! The unique scheduler identifier.
    std::size_t context_id_;

    //! The asio asynchronous event loop scheduler.
    std::shared_ptr<boost::asio::io_context> io_context_;

    //! The work-tracking executor that keep the asio scheduler running.
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_;

    //! The waiting mode used by execution loops during idle cycles.
    WaitMode wait_mode_;

  private:
    //! Execute single-threaded loop until stopped.
    template <typename IdleStrategy>
    void execute_loop_single_threaded(IdleStrategy&& idle_strategy);

    //! Execute multi-threaded loop until stopped.
    void execute_loop_multi_threaded();
};

std::ostream& operator<<(std::ostream& out, const Context& c);

//! Pool of \ref Context instances running as separate reactive schedulers.
template <typename T = Context>
class ContextPool : public ExecutorPool {
    using ExceptionHandler = std::function<void(std::exception_ptr)>;

  public:
    explicit ContextPool(std::size_t pool_size) : next_index_{0}, exception_handler_{termination_handler} {
        if (pool_size == 0) {
            throw std::logic_error("ContextPool::ContextPool pool_size is 0");
        }
        contexts_.reserve(pool_size);
    }
    explicit ContextPool(ContextPoolSettings settings) : ContextPool(settings.num_contexts) {
        for (size_t i{0}; i < settings.num_contexts; ++i) {
            add_context(T{contexts_.size(), settings.wait_mode});
        }
    }
    ~ContextPool() override {
        SILK_TRACE << "ContextPool::~ContextPool START " << this;
        stop();
        join();
        SILK_TRACE << "ContextPool::~ContextPool END " << this;
    }

    ContextPool(const ContextPool&) = delete;
    ContextPool& operator=(const ContextPool&) = delete;

    //! Add a new \ref T to the pool.
    const T& add_context(T&& context) {
        const auto num_contexts = contexts_.size();
        contexts_.emplace_back(std::move(context));
        SILK_TRACE << "ContextPool::add_context context[" << num_contexts << "] " << contexts_[num_contexts];
        return contexts_[num_contexts];
    }

    //! Start one execution thread for each context.
    virtual void start() {
        SILK_TRACE << "ContextPool::start START";

        // Create a pool of threads to run all the contexts (each context having 1 thread)
        for (std::size_t i{0}; i < contexts_.size(); ++i) {
            auto& context = contexts_[i];
            context_threads_.create_thread([&, i = i]() {
                log::set_thread_name(std::string("asio_ctx_s" + std::to_string(i)).c_str());
                SILK_TRACE << "Thread start context[" << i << "] thread_id: " << std::this_thread::get_id();
                try {
                    context.execute_loop();
                } catch (const std::exception& ex) {
                    SILK_CRIT << "ContextPool context.execute_loop exception: " << ex.what();
                    exception_handler_(std::make_exception_ptr(ex));
                } catch (...) {
                    SILK_CRIT << "ContextPool context.execute_loop unexpected exception";
                    exception_handler_(std::current_exception());
                }
                SILK_TRACE << "Thread end context[" << i << "] thread_id: " << std::this_thread::get_id();
            });
            SILK_TRACE << "ContextPool::start context[" << i << "] started: " << context.io_context();
        }

        SILK_TRACE << "ContextPool::start END";
    }

    //! Wait for termination of all execution threads.
    //!\warning This will block until \ref stop() is called.
    void join() {
        SILK_TRACE << "ContextPool::join START";

        // Wait for all threads in the pool to exit.
        SILK_TRACE << "ContextPool::join joining...";
        context_threads_.join();

        SILK_TRACE << "ContextPool::join END";
    }

    //! Stop all execution threads. This does *NOT* wait for termination: use \ref join() for that.
    void stop() {
        SILK_TRACE << "ContextPool::stop START";

        if (!stopped_.exchange(true)) {
            // Explicitly stop all context runnable components
            for (std::size_t i{0}; i < contexts_.size(); ++i) {
                contexts_[i].stop();
                SILK_TRACE << "ContextPool::stop context[" << i << "] stopped: " << contexts_[i].io_context();
            }
        }

        SILK_TRACE << "ContextPool::stop END";
    }

    //! Run one execution thread for each context waiting for termination of all execution threads.
    //!\warning This will block until \ref stop() is called.
    void run() {
        start();
        join();
    }

    [[nodiscard]] std::size_t num_contexts() const { return contexts_.size(); }

    //! Use a round-robin scheme to choose the next context to use
    T& next_context() {
        ensure(contexts_.size() > 0, "ContextPool: no context in pool");
        // Increment the next index first to make sure that different calling threads get different contexts.
        size_t index = next_index_.fetch_add(1) % contexts_.size();
        return contexts_[index];
    }

    boost::asio::io_context& next_io_context() {
        const auto& context = next_context();
        return *context.io_context();
    }

    // ExecutorPool
    [[nodiscard]] boost::asio::any_io_executor any_executor() override {
        return this->next_io_context().get_executor();
    }

    [[nodiscard]] ExecutorPool& as_executor_pool() {
        return *this;
    }

    void set_exception_handler(ExceptionHandler exception_handler) {
        exception_handler_ = std::move(exception_handler);
    }

  protected:
    static void termination_handler(std::exception_ptr) {  // NOLINT(performance-unnecessary-value-param)
        std::terminate();
    }

    //! The pool of execution contexts.
    std::vector<T> contexts_;

    //! The pool of threads running the execution contexts.
    boost::asio::detail::thread_group context_threads_;

    //! The index for obtaining next context to use (round-robin).
    std::atomic_size_t next_index_;

    //! Flag indicating if pool has been stopped.
    std::atomic_bool stopped_{false};

    //! Exception handler invoked on execution loop abnormal termination
    ExceptionHandler exception_handler_;
};

}  // namespace silkworm::concurrency
