/*
   Copyright 2024 The Silkworm Authors

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

#include <condition_variable>
#include <mutex>
#include <thread>

#include <boost/circular_buffer.hpp>

namespace silkworm {

template <class T>
/**
 * @class bounded_buffer
 * @brief A thread-safe bounded buffer implementation.
 *
 * The bounded_buffer class provides a fixed-size buffer that can be accessed by multiple threads concurrently.
 * It uses boost::circular_buffer as the underlying container and provides methods for pushing and popping items.
 * The buffer ensures that it is not full before pushing an item and not empty before popping an item.
 * The class is designed to be used in a producer-consumer scenario, where one or more threads produce items and one or more threads consume them.
 * The class is thread-safe and can be used in a multi-threaded environment.
 *
 * @tparam T The type of items stored in the buffer.
 */
class BoundedBuffer {
  public:
    typedef boost::circular_buffer<T> container_type;
    typedef typename container_type::size_type size_type;
    typedef typename container_type::value_type value_type;

    explicit BoundedBuffer(size_type capacity) : capacity_{capacity}, unread_(0), container_(capacity) {}

    void push_front(value_type&& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, std::bind(&BoundedBuffer<value_type>::is_not_full, this));
        container_.push_front(std::forward<value_type>(item));
        ++unread_;
        lock.unlock();
        not_empty_.notify_one();
    }

    void pop_back(value_type* pItem) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, std::bind(&BoundedBuffer<value_type>::is_not_empty, this));
        *pItem = container_[--unread_];
        lock.unlock();
        not_full_.notify_one();
    }

    size_type size() {
        return unread_;
    }

    size_type capacity() {
        return capacity_;
    }

  private:
    BoundedBuffer(const BoundedBuffer&) = delete;             // Disabled copy constructor
    BoundedBuffer& operator=(const BoundedBuffer&) = delete;  // Disabled assign operator

    bool is_not_empty() const { return unread_ > 0; }
    bool is_not_full() const { return unread_ < capacity_; }

    size_type capacity_;
    size_type unread_;
    container_type container_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
};

}  // namespace silkworm