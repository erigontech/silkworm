// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <functional>

#include <boost/circular_buffer.hpp>
// Apple Clang does not support std::stop_token yet, so we use boost::thread and its related facilities
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

namespace silkworm {

/**
 * @class BoundedBuffer
 * @brief A thread-safe bounded buffer implementation.
 * The bounded_buffer class provides a fixed-size buffer that can be accessed by multiple threads concurrently.
 * It uses boost::circular_buffer as the underlying container and provides methods for pushing and popping items.
 * The buffer ensures that it is not full before pushing an item and not empty before popping an item.
 * The class is designed to be used in a producer-consumer scenario, where one or more threads produce items and
 * one or more threads consume them.
 * The class is thread-safe and can be used in a multi-threaded environment.
 * @tparam T The type of items stored in the buffer.
 */
template <class T>
class BoundedBuffer {
  public:
    using size_type = typename boost::circular_buffer<T>::size_type;
    using value_type = typename boost::circular_buffer<T>::value_type;

    explicit BoundedBuffer(size_type capacity) : capacity_{capacity}, unread_(0), container_(capacity) {}

    BoundedBuffer(const BoundedBuffer&) = delete;             // Disabled copy constructor
    BoundedBuffer& operator=(const BoundedBuffer&) = delete;  // Disabled assign operator

    void push_front(value_type&& item) {
        boost::unique_lock<boost::mutex> lock(mutex_);

        not_full_.wait(lock, [&] { return is_stopped() || is_not_full(); });

        if (is_stopped()) {  // If the buffer is stopped, do not push the item
            return;
        }

        container_.push_front(std::move(item));
        ++unread_;
        lock.unlock();
        not_empty_.notify_one();
    }

    void peek_back(value_type* item) {
        boost::unique_lock<boost::mutex> lock(mutex_);

        not_empty_.wait(lock, [&] { return is_stopped() || is_not_empty(); });

        if (is_stopped()) {  // If the buffer is stopped, do not peek the item
            item = nullptr;
            return;
        }

        *item = container_[unread_ - 1];
        lock.unlock();
    }

    void pop_back(value_type* item) {
        boost::unique_lock<boost::mutex> lock(mutex_);

        not_empty_.wait(lock, [&] { return is_stopped() || is_not_empty(); });

        if (is_stopped()) {  // If the buffer is stopped, do not pop the item
            item = nullptr;
            return;
        }

        *item = container_[--unread_];
        lock.unlock();
        not_full_.notify_one();
    }

    void terminate_and_release_all() {
        boost::unique_lock<boost::mutex> lock(mutex_);
        stop_ = true;
        lock.unlock();
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    bool is_stopped() const {
        return stop_;
    }

    size_type size() const {
        return unread_;
    }

    size_type capacity() const {
        return capacity_;
    }

  private:
    bool is_not_empty() const { return unread_ > 0; }
    bool is_not_full() const { return unread_ < capacity_; }

    bool stop_{false};
    size_type capacity_;
    size_type unread_;
    boost::circular_buffer<T> container_;
    boost::mutex mutex_;
    boost::condition_variable not_empty_;
    boost::condition_variable not_full_;
};

}  // namespace silkworm