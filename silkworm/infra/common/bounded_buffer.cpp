
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
class bounded_buffer {
  public:
    typedef boost::circular_buffer<T> container_type;
    typedef typename container_type::size_type size_type;
    typedef typename container_type::value_type value_type;
    typedef typename boost::call_traits<value_type>::param_type param_type; // `param_type` represents the "best" way to pass a parameter of type `value_type` to a method.

    explicit bounded_buffer(size_type capacity) : unread_(0), container_(capacity) {}

    void push_front(param_type item) {  
        boost::mutex::scoped_lock lock(mutex_);
        not_full_.wait(lock, boost::bind(&bounded_buffer<value_type>::is_not_full, this));
        container_.push_front(item);
        ++unread_;
        lock.unlock();
        not_empty_.notify_one();
    }

    void pop_back(value_type* pItem) {
        boost::mutex::scoped_lock lock(mutex_);
        not_empty_.wait(lock, boost::bind(&bounded_buffer<value_type>::is_not_empty, this));
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
    bounded_buffer(const bounded_buffer&) = delete;             // Disabled copy constructor
    bounded_buffer& operator=(const bounded_buffer&) = delete;  // Disabled assign operator

    bool is_not_empty() const { return unread_ > 0; }
    bool is_not_full() const { return unread_ < container_.capacity(); }

    size_type unread_;
    container_type container_;
    boost::mutex mutex_;
    boost::condition_variable not_empty_;
    boost::condition_variable not_full_;
};

}  // namespace silkworm