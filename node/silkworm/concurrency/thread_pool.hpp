#pragma once
#ifndef SILKWORM_CONCURRENCY_THREAD_POOL_HPP_
#define SILKWORM_CONCURRENCY_THREAD_POOL_HPP_

/**
 * @file thread_pool.hpp
 * @author Barak Shoshany (baraksh@gmail.com) (http://baraksh.com)
 * @copyright Copyright (c) 2021 Barak Shoshany. Licensed under the MIT license. If you use this library in published
 * research, please cite it as follows:
 *  - Barak Shoshany, "A C++17 Thread Pool for High-Performance Scientific Computing", doi:10.5281/zenodo.4742687,
 * arXiv:2105.00613 (May 2021)
 *
 * Modified for Silkworm.
 *
 * @brief A C++17 thread pool for high-performance scientific computing.
 * @details A modern C++17-compatible thread pool implementation, built from scratch with high-performance scientific
 * computing in mind. The thread pool was extensively tested on both AMD and Intel CPUs with up to 40 cores and 80
 * threads. Other features include automatic generation of futures and easy parallelization of loops. Two helper classes
 * enable synchronizing printing to an output stream by different threads and measuring execution time for benchmarking
 * purposes. Please visit the GitHub repository at https://github.com/bshoshany/thread-pool for documentation and
 * updates, or to submit feature requests and bug reports.
 * The thread pool uses boost::thread instead of std::thread because the latter does not support setting custom stack
 * sizes. See also http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p2019r0.pdf
 */

#include <atomic>       // std::atomic
#include <chrono>       // std::chrono
#include <cstdint>      // std::int_fast64_t, std::uint_fast32_t
#include <functional>   // std::function
#include <future>       // std::future, std::promise
#include <iostream>     // std::cout, std::ostream
#include <memory>       // std::shared_ptr, std::unique_ptr
#include <mutex>        // std::mutex, std::scoped_lock
#include <queue>        // std::queue
#include <thread>       // std::this_thread
#include <type_traits>  // std::common_type_t, std::decay_t, std::enable_if_t, std::is_void_v, std::invoke_result_t
#include <utility>      // std::move

#include <boost/thread/thread.hpp>  // boost::thread

namespace silkworm {

// ============================================================================================= //
//                                    Begin class thread_pool                                    //

/**
 * @brief A C++17 thread pool class. The user submits tasks to be executed into a queue. Whenever a thread becomes
 * available, it pops a task from the queue and executes it. Each task is automatically assigned a future, which can be
 * used to wait for the task to finish executing and/or obtain its eventual return value.
 */
class thread_pool {
    typedef std::uint_fast32_t ui32;
    typedef std::uint_fast64_t ui64;

  public:
    // ============================
    // Constructors and destructors
    // ============================

    /**
     * @brief Construct a new thread pool.
     *
     * @param thread_count The number of threads to use. The default value is the total number of hardware threads
     * available, as reported by the implementation. With a hyperthreaded CPU, this will be twice the number of CPU
     * cores.
     * @param stack_size The stack size to set for each created thread. If the argument is zero, the default OS value
     * will be used instead.
     */
    explicit thread_pool(ui32 thread_count = std::thread::hardware_concurrency(), std::size_t stack_size = 0)
        : thread_count_(thread_count ? thread_count : 1),
          threads_(new boost::thread[thread_count_]),
          stack_size_(stack_size) {
        create_threads();
    }

    /**
     * @brief Destruct the thread pool. Waits for all tasks to complete, then destroys all threads. Note that if the
     * variable paused is set to true, then any tasks still in the queue will never be executed.
     */
    ~thread_pool() {
        wait_for_tasks();
        running_ = false;
        destroy_threads();
    }

    // =======================
    // Public member functions
    // =======================

    /**
     * @brief Get the number of tasks currently waiting in the queue to be executed by the threads.
     *
     * @return The number of queued tasks.
     */
    ui32 get_tasks_queued() const {
        const std::scoped_lock lock(queue_mutex_);
        return static_cast<ui32>(tasks_.size());
    }

    /**
     * @brief Get the number of tasks currently being executed by the threads.
     *
     * @return The number of running tasks.
     */
    ui32 get_tasks_running() const { return tasks_total_ - get_tasks_queued(); }

    /**
     * @brief Get the total number of unfinished tasks - either still in the queue, or running in a thread.
     *
     * @return The total number of tasks.
     */
    ui32 get_tasks_total() const { return tasks_total_; }

    /**
     * @brief Get the number of threads in the pool.
     *
     * @return The number of threads.
     */
    ui32 get_thread_count() const { return thread_count_; }

    /**
     * @brief Parallelize a loop by splitting it into blocks, submitting each block separately to the thread pool, and
     * waiting for all blocks to finish executing. The user supplies a loop function, which will be called once per
     * block and should iterate over the block's range.
     *
     * @tparam T1 The type of the first index in the loop. Should be a signed or unsigned integer.
     * @tparam T2 The type of the index after the last index in the loop. Should be a signed or unsigned integer. If T1
     * is not the same as T2, a common type will be automatically inferred.
     * @tparam F The type of the function to loop through.
     * @param first_index The first index in the loop.
     * @param index_after_last The index after the last index in the loop. The loop will iterate from first_index to
     * (index_after_last - 1) inclusive. In other words, it will be equivalent to "for (T i = first_index; i <
     * index_after_last; i++)". Note that if first_index == index_after_last, the function will terminate without doing
     * anything.
     * @param loop The function to loop through. Will be called once per block. Should take exactly two arguments: the
     * first index in the block and the index after the last index in the block. loop(start, end) should typically
     * involve a loop of the form "for (T i = start; i < end; i++)".
     * @param num_blocks The maximum number of blocks to split the loop into. The default is to use the number of
     * threads in the pool.
     */
    template <typename T1, typename T2, typename F>
    void parallelize_loop(const T1& first_index, const T2& index_after_last, const F& loop, ui32 num_blocks = 0) {
        typedef std::common_type_t<T1, T2> T;
        T the_first_index = first_index;
        T last_index = index_after_last;
        if (the_first_index == last_index) return;
        if (last_index < the_first_index) {
            T temp = last_index;
            last_index = the_first_index;
            the_first_index = temp;
        }
        last_index--;
        if (num_blocks == 0) {
            num_blocks = thread_count_;
        }
        ui64 total_size = last_index - the_first_index + 1;
        ui64 block_size = total_size / num_blocks;
        if (block_size == 0) {
            block_size = 1;
            num_blocks = total_size > 1 ? static_cast<ui32>(total_size) : 1;
        }
        std::atomic<ui32> blocks_running = 0;
        for (ui32 t = 0; t < num_blocks; t++) {
            T start = static_cast<T>(t * block_size) + the_first_index;
            T end = (t == num_blocks - 1) ? last_index + 1 : (static_cast<T>((t + 1) * block_size) + the_first_index);
            blocks_running++;
            push_task([start, end, &loop, &blocks_running] {
                loop(start, end);
                blocks_running--;
            });
        }
        while (blocks_running != 0) {
            sleep_or_yield();
        }
    }

    /**
     * @brief Push a function with no arguments or return value into the task queue.
     *
     * @tparam F The type of the function.
     * @param task The function to push.
     */
    template <typename F>
    void push_task(const F& task) {
        ++tasks_total_;
        {
            const std::scoped_lock lock(queue_mutex_);
            tasks_.push(std::function<void()>(task));
        }
    }

    /**
     * @brief Push a function with arguments, but no return value, into the task queue.
     * @details The function is wrapped inside a lambda in order to hide the arguments, as the tasks in the queue must
     * be of type std::function<void()>, so they cannot have any arguments or return value. If no arguments are
     * provided, the other overload will be used, in order to avoid the (slight) overhead of using a lambda.
     *
     * @tparam F The type of the function.
     * @tparam A The types of the arguments.
     * @param task The function to push.
     * @param args The arguments to pass to the function.
     */
    template <typename F, typename... A>
    void push_task(const F& task, const A&... args) {
        push_task([task, args...] { task(args...); });
    }

    /**
     * @brief Reset the number of threads in the pool. Waits for all currently running tasks to be completed, then
     * destroys all threads in the pool and creates a new thread pool with the new number of threads. Any tasks that
     * were waiting in the queue before the pool was reset will then be executed by the new threads. If the pool was
     * paused before resetting it, the new pool will be paused as well.
     *
     * @param thread_count The number of threads to use. The default value is the total number of hardware threads
     * available, as reported by the implementation. With a hyperthreaded CPU, this will be twice the number of CPU
     * cores.
     */
    void reset(ui32 thread_count = std::thread::hardware_concurrency()) {
        bool was_paused = paused;
        paused = true;
        wait_for_tasks();
        running_ = false;
        destroy_threads();
        thread_count_ = thread_count ? thread_count : 1;
        threads_.reset(new boost::thread[thread_count_]);
        paused = was_paused;
        running_ = true;
        create_threads();
    }

    /**
     * @brief Submit a function with zero or more arguments and no return value into the task queue, and get an
     * std::future<bool> that will be set to true upon completion of the task.
     *
     * @tparam F The type of the function.
     * @tparam A The types of the zero or more arguments to pass to the function.
     * @param task The function to submit.
     * @param args The zero or more arguments to pass to the function.
     * @return A future to be used later to check if the function has finished its execution.
     */
    template <typename F, typename... A,
              typename = std::enable_if_t<std::is_void_v<std::invoke_result_t<std::decay_t<F>, std::decay_t<A>...>>>>
    std::future<bool> submit(const F& task, const A&... args) {
        std::shared_ptr<std::promise<bool>> task_promise(new std::promise<bool>);
        std::future<bool> future = task_promise->get_future();
        push_task([task, args..., task_promise] {
            try {
                task(args...);
                task_promise->set_value(true);
            } catch (...) {
                try {
                    task_promise->set_exception(std::current_exception());
                } catch (...) {
                }
            }
        });
        return future;
    }

    /**
     * @brief Submit a function with zero or more arguments and a return value into the task queue, and get a future for
     * its eventual returned value.
     *
     * @tparam F The type of the function.
     * @tparam A The types of the zero or more arguments to pass to the function.
     * @tparam R The return type of the function.
     * @param task The function to submit.
     * @param args The zero or more arguments to pass to the function.
     * @return A future to be used later to obtain the function's returned value, waiting for it to finish its execution
     * if needed.
     */
    template <typename F, typename... A, typename R = std::invoke_result_t<std::decay_t<F>, std::decay_t<A>...>,
              typename = std::enable_if_t<!std::is_void_v<R>>>
    std::future<R> submit(const F& task, const A&... args) {
        std::shared_ptr<std::promise<R>> task_promise(new std::promise<R>);
        std::future<R> future = task_promise->get_future();
        push_task([task, args..., task_promise] {
            try {
                task_promise->set_value(task(args...));
            } catch (...) {
                try {
                    task_promise->set_exception(std::current_exception());
                } catch (...) {
                }
            }
        });
        return future;
    }

    /**
     * @brief Wait for tasks to be completed. Normally, this function waits for all tasks, both those that are currently
     * running in the threads and those that are still waiting in the queue. However, if the variable paused is set to
     * true, this function only waits for the currently running tasks (otherwise it would wait forever). To wait for a
     * specific task, use submit() instead, and call the wait() member function of the generated future.
     */
    void wait_for_tasks() {
        while (true) {
            if (!paused) {
                if (tasks_total_ == 0) break;
            } else {
                if (get_tasks_running() == 0) break;
            }
            sleep_or_yield();
        }
    }

    // ===========
    // Public data
    // ===========

    /**
     * @brief An atomic variable indicating to the workers to pause. When set to true, the workers temporarily stop
     * popping new tasks out of the queue, although any tasks already executed will keep running until they are done.
     * Set to false again to resume popping tasks.
     */
    std::atomic<bool> paused = false;

    /**
     * @brief The duration, in microseconds, that the worker function should sleep for when it cannot find any tasks in
     * the queue. If set to 0, then instead of sleeping, the worker function will execute std::this_thread::yield() if
     * there are no tasks in the queue. The default value is 1000.
     */
    ui32 sleep_duration = 1000;

  private:
    // ========================
    // Private member functions
    // ========================

    /**
     * @brief Create the threads in the pool and assign a worker to each thread.
     */
    void create_threads() {
        boost::thread::attributes attrs;
        if (stack_size_) {
            attrs.set_stack_size(stack_size_);
        }
        for (ui32 i = 0; i < thread_count_; i++) {
            threads_[i] = boost::thread(attrs, boost::bind(&thread_pool::worker, this));
        }
    }

    /**
     * @brief Destroy the threads in the pool by joining them.
     */
    void destroy_threads() {
        for (ui32 i = 0; i < thread_count_; i++) {
            threads_[i].join();
        }
    }

    /**
     * @brief Try to pop a new task out of the queue.
     *
     * @param task A reference to the task. Will be populated with a function if the queue is not empty.
     * @return true if a task was found, false if the queue is empty.
     */
    bool pop_task(std::function<void()>& task) {
        const std::scoped_lock lock(queue_mutex_);
        if (tasks_.empty()) {
            return false;
        } else {
            task = std::move(tasks_.front());
            tasks_.pop();
            return true;
        }
    }

    /**
     * @brief Sleep for sleep_duration microseconds. If that variable is set to zero, yield instead.
     *
     */
    void sleep_or_yield() {
        if (sleep_duration)
            std::this_thread::sleep_for(std::chrono::microseconds(sleep_duration));
        else
            std::this_thread::yield();
    }

    /**
     * @brief A worker function to be assigned to each thread in the pool. Continuously pops tasks out of the queue and
     * executes them, as long as the atomic variable running is set to true.
     */
    void worker() {
        while (running_) {
            std::function<void()> task;
            if (!paused && pop_task(task)) {
                task();
                --tasks_total_;
            } else {
                sleep_or_yield();
            }
        }
    }

    // ============
    // Private data
    // ============

    /**
     * @brief A mutex to synchronize access to the task queue by different threads.
     */
    mutable std::mutex queue_mutex_ = {};

    /**
     * @brief An atomic variable indicating to the workers to keep running. When set to false, the workers permanently
     * stop working.
     */
    std::atomic<bool> running_ = true;

    /**
     * @brief A queue of tasks to be executed by the threads.
     */
    std::queue<std::function<void()>> tasks_ = {};

    /**
     * @brief The number of threads in the pool.
     */
    ui32 thread_count_;

    /**
     * @brief A smart pointer to manage the memory allocated for the threads.
     */
    std::unique_ptr<boost::thread[]> threads_;

    /**
     * @brief An atomic variable to keep track of the total number of unfinished tasks - either still in the queue, or
     * running in a thread.
     */
    std::atomic<ui32> tasks_total_ = 0;

    /**
     * @brief The stack size of created threads. 0 means default OS value.
     */
    std::size_t stack_size_ = 0;
};

//                                     End class thread_pool                                     //
// ============================================================================================= //

}  // namespace silkworm

#endif  // SILKWORM_CONCURRENCY_THREAD_POOL_HPP_
