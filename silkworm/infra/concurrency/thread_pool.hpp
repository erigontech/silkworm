// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <atomic>              // std::atomic
#include <condition_variable>  // std::condition_variable
#include <exception>           // std::current_exception
#include <functional>          // std::bind, std::function, std::invoke
#include <future>              // std::future, std::promise
#include <memory>              // std::make_shared, std::make_unique, std::shared_ptr, std::unique_ptr
#include <mutex>               // std::mutex, std::scoped_lock, std::unique_lock
#include <queue>               // std::queue
#include <thread>              // std::thread::hardware_concurrency
#include <type_traits>         // std::decay_t, std::invoke_result_t, std::is_void_v
#include <utility>             // std::forward, std::move, std::swap

#include <boost/thread/thread.hpp>  // boost::thread

namespace silkworm {

/**
 * @brief A fast, lightweight, and easy-to-use C++17 thread pool.
 */
class ThreadPool {
  public:
    // ============================
    // Constructors and destructors
    // ============================

    /**
     * @brief Construct a new thread pool.
     *
     * @param thread_count The number of threads to use. The default value is the total number of hardware threads
     * available, as reported by the implementation. This is usually determined by the number of cores in the CPU.
     * If a core is hyper-threaded, it will count as two threads.
     * @param stack_size The stack size to set for each created thread. If the argument is zero, the default OS value
     * will be used instead.
     */
    explicit ThreadPool(unsigned thread_count = std::thread::hardware_concurrency(), size_t stack_size = 0)
        : thread_count_(thread_count ? thread_count : 1),
          threads_(std::make_unique<boost::thread[]>(thread_count_)) {
        create_threads(stack_size);
    }

    // Not copyable nor movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /**
     * @brief Destruct the thread pool. Waits for all tasks to complete, then destroys all threads. Note that
     * if the pool is paused, then any tasks still in the queue will never be executed.
     */
    ~ThreadPool() {
        wait_for_tasks();
        destroy_threads();
    }

    // =======================
    // Public member functions
    // =======================

    /**
     * @brief Get the total number of unfinished tasks: either still in the queue, or running in a thread.
     *
     * @return The total number of tasks.
     */
    size_t get_tasks_total() const {
        return tasks_total_;
    }

    /**
     * @brief Get the number of threads in the pool.
     *
     * @return The number of threads.
     */
    unsigned get_thread_count() const {
        return thread_count_;
    }

    /**
     * @brief Check whether the pool is currently paused.
     *
     * @return true if the pool is paused, false if it is not paused.
     */
    bool is_paused() const {
        return paused_;
    }

    /**
     * @brief Pause the pool. The workers will temporarily stop retrieving new tasks out of the queue,
     * although any tasks already executed will keep running until they are finished.
     */
    void pause() {
        paused_ = true;
    }

    /**
     * @brief Push a function with zero or more arguments, but no return value, into the task queue. Does not return
     * a future, so the user must use wait_for_tasks() or some other method to ensure that the task finishes executing,
     * otherwise bad things will happen.
     *
     * @tparam F The type of the function.
     * @tparam A The types of the arguments.
     * @param task The function to push.
     * @param args The zero or more arguments to pass to the function. Note that if the task is a class member function,
     * the first argument must be a pointer to the object, i.e. &object (or this), followed by the actual arguments.
     */
    template <typename F, typename... A>
    void push_task(F&& task, A&&... args) {
        // NOLINTNEXTLINE(modernize-avoid-bind)
        std::function<void()> task_function = std::bind(std::forward<F>(task), std::forward<A>(args)...);
        {
            const std::scoped_lock tasks_lock(tasks_mutex_);
            tasks_.push(task_function);
            ++tasks_total_;
        }
        task_available_cv_.notify_one();
    }

    /**
     * @brief Submit a function with zero or more arguments into the task queue. If the function has a return value,
     * get a future for the eventual returned value. If the function has no return value, get an std::future<void>
     * which can be used to wait until the task finishes.
     *
     * @tparam F The type of the function.
     * @tparam A The types of the zero or more arguments to pass to the function.
     * @tparam R The return type of the function (can be void).
     * @param task The function to submit.
     * @param args The zero or more arguments to pass to the function. Note that if the task is a class member function,
     * the first argument must be a pointer to the object, i.e. &object (or this), followed by the actual arguments.
     * @return A future to be used later to wait for the function to finish executing and/or obtain its returned value
     * if it has one.
     */
    template <typename F, typename... A, typename R = std::invoke_result_t<std::decay_t<F>, std::decay_t<A>...>>
    [[nodiscard]] std::future<R> submit(F&& task, A&&... args) {
        // NOLINTNEXTLINE(modernize-avoid-bind)
        std::function<R()> task_function = std::bind(std::forward<F>(task), std::forward<A>(args)...);
        std::shared_ptr<std::promise<R>> task_promise = std::make_shared<std::promise<R>>();
        push_task(
            [task_function, task_promise] {
                try {
                    if constexpr (std::is_void_v<R>) {
                        std::invoke(task_function);
                        task_promise->set_value();
                    } else {
                        task_promise->set_value(std::invoke(task_function));
                    }
                } catch (...) {
                    try {
                        task_promise->set_exception(std::current_exception());
                    } catch (...) {
                    }
                }
            });
        return task_promise->get_future();
    }

    /**
     * @brief Unpause the pool. The workers will resume retrieving new tasks out of the queue.
     */
    void unpause() {
        paused_ = false;
    }

    /**
     * @brief Wait for tasks to be completed. Normally, this function waits for all tasks, both those that are currently
     * running in the threads and those that are still waiting in the queue. However, if the pool is paused, this
     * function only waits for the currently running tasks (otherwise it would wait forever). Note: To wait for just one
     * specific task, use submit() instead, and call the wait() member function of the generated future.
     */
    void wait_for_tasks() {
        if (!waiting_) {
            waiting_ = true;
            std::unique_lock<std::mutex> tasks_lock(tasks_mutex_);
            task_done_cv_.wait(tasks_lock, [this] { return (tasks_total_ == (paused_ ? tasks_.size() : 0)); });
            waiting_ = false;
        }
    }

  private:
    // ========================
    // Private member functions
    // ========================

    /**
     * @brief Create the threads in the pool and assign a worker to each thread.
     * @param stack_size The stack size of created threads. 0 means default OS value.
     */
    void create_threads(size_t stack_size) {
        running_ = true;
        boost::thread::attributes attrs;
        if (stack_size) {
            attrs.set_stack_size(stack_size);
        }
        for (unsigned i = 0; i < thread_count_; ++i) {
            threads_[i] = boost::thread(attrs, [this] { worker(); });
        }
    }

    /**
     * @brief Destroy the threads in the pool.
     */
    void destroy_threads() {
        running_ = false;
        {
            const std::scoped_lock tasks_lock(tasks_mutex_);
            task_available_cv_.notify_all();
        }
        for (unsigned i = 0; i < thread_count_; ++i) {
            threads_[i].join();
        }
    }

    /**
     * @brief A worker function to be assigned to each thread in the pool. Waits until it is notified by push_task()
     * that a task is available, and then retrieves the task from the queue and executes it. Once the task finishes,
     * the worker notifies wait_for_tasks() in case it is waiting.
     */
    void worker() {
        while (running_) {
            std::function<void()> task;
            std::unique_lock<std::mutex> tasks_lock(tasks_mutex_);
            task_available_cv_.wait(tasks_lock, [this] { return !tasks_.empty() || !running_; });
            if (running_ && !paused_) {
                task = std::move(tasks_.front());
                tasks_.pop();
                tasks_lock.unlock();
                task();
                tasks_lock.lock();
                --tasks_total_;
                if (waiting_)
                    task_done_cv_.notify_one();
            }
        }
    }

    // ============
    // Private data
    // ============

    /**
     * @brief An atomic variable indicating whether the workers should pause. When set to true, the workers temporarily
     * stop retrieving new tasks out of the queue, although any tasks already executed will keep running until they are
     * finished. When set to false again, the workers resume retrieving tasks.
     */
    std::atomic<bool> paused_ = false;

    /**
     * @brief An atomic variable indicating to the workers to keep running. When set to false, the workers permanently
     * stop working.
     */
    std::atomic<bool> running_ = false;

    /**
     * @brief A condition variable used to notify worker() that a new task has become available.
     */
    std::condition_variable task_available_cv_ = {};

    /**
     * @brief A condition variable used to notify wait_for_tasks() that a tasks is done.
     */
    std::condition_variable task_done_cv_ = {};

    /**
     * @brief A queue of tasks to be executed by the threads.
     */
    std::queue<std::function<void()>> tasks_ = {};

    /**
     * @brief An atomic variable to keep track of the total number of unfinished tasks - either still in the queue,
     * or running in a thread.
     */
    std::atomic<size_t> tasks_total_ = 0;

    /**
     * @brief A mutex to synchronize access to the task queue by different threads.
     */
    mutable std::mutex tasks_mutex_ = {};

    /**
     * @brief The number of threads in the pool.
     */
    unsigned thread_count_ = 0;

    /**
     * @brief A smart pointer to manage the memory allocated for the threads.
     */
    std::unique_ptr<boost::thread[]> threads_ = nullptr;

    /**
     * @brief An atomic variable indicating that wait_for_tasks() is active and expects to be notified whenever a task
     * is done.
     */
    std::atomic<bool> waiting_ = false;
};

}  // namespace silkworm
