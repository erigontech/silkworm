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

#include <deque>
#include <iostream>
#include <list>
#include <string>

#include <boost/bind.hpp>
#include <boost/call_traits.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/timer/timer.hpp>

#include <silkworm/infra/common/stopwatch.hpp>

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
    typedef typename boost::call_traits<value_type>::param_type param_type;  // `param_type` represents the "best" way to pass a parameter of type `value_type` to a method.

    explicit BoundedBuffer(size_type capacity) : unread_(0), container_(capacity) {}

    void push_front(param_type item) {
        boost::mutex::scoped_lock lock(mutex_);
        not_full_.wait(lock, boost::bind(&BoundedBuffer<value_type>::is_not_full, this));
        container_.push_front(item);
        ++unread_;
        lock.unlock();
        not_empty_.notify_one();
    }

    void pop_back(value_type* pItem) {
        boost::mutex::scoped_lock lock(mutex_);
        not_empty_.wait(lock, boost::bind(&BoundedBuffer<value_type>::is_not_empty, this));
        *pItem = container_[--unread_];
        lock.unlock();
        not_full_.notify_one();
    }

    size_type size() {
        return unread_;
    }

    size_type capacity() {
        boost::unique_lock<boost::mutex> lock(mutex_);
        return container_.capacity();
    }

  private:
    BoundedBuffer(const BoundedBuffer&) = delete;             // Disabled copy constructor
    BoundedBuffer& operator=(const BoundedBuffer&) = delete;  // Disabled assign operator

    bool is_not_empty() const { return unread_ > 0; }
    bool is_not_full() const { return unread_ < container_.capacity(); }

    size_type unread_;
    container_type container_;
    boost::mutex mutex_;
    boost::condition_variable not_empty_;
    boost::condition_variable not_full_;
};

}  // namespace silkworm