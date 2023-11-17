/*
   Copyright 2023 The Silkworm Authors

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

//
// Copyright (c) 2003-2021 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <exception>
#include <memory>
#include <type_traits>
#include <utility>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/execution_context.hpp>
#include <boost/asio/executor.hpp>
#include <boost/asio/is_executor.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::concurrency::detail {

using boost::asio::awaitable;
using boost::asio::cancellation_signal;
using boost::asio::cancellation_slot;
using boost::asio::cancellation_state;
using boost::asio::cancellation_type_t;
using boost::asio::dispatch;
using boost::asio::enable_total_cancellation;
using boost::asio::get_associated_cancellation_slot;
using boost::asio::post;
using boost::asio::result_of;
using boost::asio::use_awaitable_t;
using boost::asio::detail::awaitable_as_function;
using boost::asio::detail::awaitable_handler;
using boost::asio::detail::awaitable_thread_entry_point;
using boost::asio::detail::awaitable_thread_has_context_switched;
using boost::asio::detail::make_co_spawn_work_guard;

template <typename T, typename Executor, typename F, typename Handler>
awaitable<awaitable_thread_entry_point, Executor> co_spawn_entry_point(
    awaitable<T, Executor>*,
    Executor ex,
    F f,
    Handler handler) {
    auto spawn_work = make_co_spawn_work_guard(ex);
    auto handler_work = make_co_spawn_work_guard(
        boost::asio::get_associated_executor(handler, ex));

    (void)co_await (dispatch)(
        use_awaitable_t<Executor>{__FILE__, __LINE__, "co_spawn_entry_point"});

    (co_await awaitable_thread_has_context_switched{}) = false;
    std::exception_ptr e = nullptr;
    bool done = false;
    try {
        T t = co_await f();

        done = true;

        bool switched = (co_await awaitable_thread_has_context_switched{});
        if (!switched) {
            (void)co_await (post)(
                use_awaitable_t<Executor>{__FILE__,
                                          __LINE__, "co_spawn_entry_point"});
        }

        (dispatch)(handler_work.get_executor(),
                   [handler = std::move(handler), t = std::move(t)]() mutable {
                       std::move(handler)(std::exception_ptr(), std::move(t));
                   });

        co_return;
    } catch (...) {
        if (done)
            throw;

        e = std::current_exception();
    }

    bool switched = (co_await awaitable_thread_has_context_switched{});
    if (!switched) {
        (void)co_await (post)(
            use_awaitable_t<Executor>{__FILE__, __LINE__, "co_spawn_entry_point"});
    }

    (dispatch)(handler_work.get_executor(),
               [handler = std::move(handler), e]() mutable {
                   std::move(handler)(e, T());
               });
}

template <typename Executor, typename F, typename Handler>
awaitable<awaitable_thread_entry_point, Executor> co_spawn_entry_point(
    awaitable<void, Executor>*,
    Executor ex,
    F f,
    Handler handler) {
    auto spawn_work = make_co_spawn_work_guard(ex);
    auto handler_work = make_co_spawn_work_guard(
        boost::asio::get_associated_executor(handler, ex));

    (void)co_await (dispatch)(
        use_awaitable_t<Executor>{__FILE__, __LINE__, "co_spawn_entry_point"});

    (co_await awaitable_thread_has_context_switched{}) = false;
    std::exception_ptr e = nullptr;
    try {
        co_await f();
    } catch (...) {
        e = std::current_exception();
    }

    bool switched = (co_await awaitable_thread_has_context_switched{});
    if (!switched) {
        (void)co_await (post)(
            use_awaitable_t<Executor>{__FILE__, __LINE__, "co_spawn_entry_point"});
    }

    (dispatch)(handler_work.get_executor(),
               [handler = std::move(handler), e]() mutable {
                   std::move(handler)(e);
               });
}

template <typename Handler, typename Executor, typename = void>
class co_spawn_cancellation_handler {
  public:
    co_spawn_cancellation_handler(const Handler&, Executor ex)
        : signal_(std::make_shared<cancellation_signal>()),
          ex_(std::move(ex)) {
    }

    cancellation_slot slot() {
        return signal_->slot();
    }

    void operator()(cancellation_type_t type) {
        auto signal_weak_ptr = std::weak_ptr<cancellation_signal>(signal_);
        boost::asio::dispatch(ex_, [signal_weak_ptr = std::move(signal_weak_ptr), type] {
            auto signal = signal_weak_ptr.lock();
            if (signal) {
                signal->emit(type);
            }
        });
    }

  private:
    std::shared_ptr<cancellation_signal> signal_;
    Executor ex_;
};

template <typename Handler, typename Executor>
class co_spawn_cancellation_handler<
    Handler,
    Executor,
    typename std::enable_if<std::is_same<typename boost::asio::associated_executor<Handler, Executor>::asio_associated_executor_is_unspecialised, void>::value>::type> {
  public:
    co_spawn_cancellation_handler(const Handler&, const Executor&) {
    }

    cancellation_slot slot() {
        return signal_.slot();
    }

    void operator()(cancellation_type_t type) {
        signal_.emit(type);
    }

  private:
    cancellation_signal signal_;
};

template <typename Executor>
class initiate_co_spawn {
  public:
    typedef Executor executor_type;

    template <typename OtherExecutor>
    explicit initiate_co_spawn(OtherExecutor ex)
        : ex_(std::move(ex)) {
    }

    executor_type get_executor() const BOOST_ASIO_NOEXCEPT {
        return ex_;
    }

    template <typename Handler, typename F>
    void operator()(Handler&& handler, F&& f) const {
        typedef typename result_of<F()>::type awaitable_type;
        typedef typename std::decay<Handler>::type handler_type;
        typedef co_spawn_cancellation_handler<handler_type, Executor> cancel_handler_type;

        auto slot = boost::asio::get_associated_cancellation_slot(handler);
        cancel_handler_type* cancel_handler =
            slot.is_connected()
                ? &slot.template emplace<cancel_handler_type>(handler, ex_)
                : nullptr;

        cancellation_slot proxy_slot(
            cancel_handler
                ? cancel_handler->slot()
                : cancellation_slot());

        cancellation_state cancel_state(proxy_slot);

        auto a = (co_spawn_entry_point)(static_cast<awaitable_type*>(nullptr),
                                        ex_,
                                        std::forward<F>(f),
                                        std::forward<Handler>(handler));
        awaitable_handler<executor_type, void>(
            std::move(a),
            ex_,
            proxy_slot,
            cancel_state)
            .launch();
    }

  private:
    Executor ex_;
};

}  // namespace silkworm::concurrency::detail

namespace silkworm::concurrency {

template <
    typename Executor,
    typename T,
    typename AwaitableExecutor,
    BOOST_ASIO_COMPLETION_TOKEN_FOR(
        void(std::exception_ptr, T)) CompletionToken>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    CompletionToken,
    void(std::exception_ptr, T))
    co_spawn_sw(
        const Executor& ex,
        boost::asio::awaitable<T, AwaitableExecutor> a,
        CompletionToken&& token,
        typename boost::asio::constraint<
            (boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value) && std::is_convertible<Executor, AwaitableExecutor>::value>::type = 0) {
    return boost::asio::async_initiate<CompletionToken, void(std::exception_ptr, T)>(
        detail::initiate_co_spawn<AwaitableExecutor>(AwaitableExecutor(ex)),
        token,
        detail::awaitable_as_function<T, AwaitableExecutor>(std::move(a)));
}

template <
    typename Executor,
    typename AwaitableExecutor,
    BOOST_ASIO_COMPLETION_TOKEN_FOR(
        void(std::exception_ptr)) CompletionToken>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    CompletionToken,
    void(std::exception_ptr))
    co_spawn_sw(
        const Executor& ex,
        boost::asio::awaitable<void, AwaitableExecutor> a,
        CompletionToken&& token,
        typename boost::asio::constraint<
            (boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value) && std::is_convertible<Executor, AwaitableExecutor>::value>::type = 0) {
    return boost::asio::async_initiate<CompletionToken, void(std::exception_ptr)>(
        detail::initiate_co_spawn<AwaitableExecutor>(AwaitableExecutor(ex)),
        token,
        detail::awaitable_as_function<void, AwaitableExecutor>(std::move(a)));
}

template <
    typename ExecutionContext,
    typename T,
    typename AwaitableExecutor,
    BOOST_ASIO_COMPLETION_TOKEN_FOR(
        void(std::exception_ptr, T)) CompletionToken>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    CompletionToken,
    void(std::exception_ptr, T))
    co_spawn_sw(
        ExecutionContext& ctx,
        boost::asio::awaitable<T, AwaitableExecutor> a,
        CompletionToken&& token,
        typename boost::asio::constraint<
            std::is_convertible<ExecutionContext&, boost::asio::execution_context&>::value && std::is_convertible<typename ExecutionContext::executor_type,
                                                                                                                  AwaitableExecutor>::value>::type = 0) {
    return (co_spawn_sw)(ctx.get_executor(),
                         std::move(a),
                         std::forward<CompletionToken>(token));
}

template <
    typename ExecutionContext,
    typename AwaitableExecutor,
    BOOST_ASIO_COMPLETION_TOKEN_FOR(
        void(std::exception_ptr)) CompletionToken>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    CompletionToken,
    void(std::exception_ptr))
    co_spawn_sw(
        ExecutionContext& ctx,
        boost::asio::awaitable<void, AwaitableExecutor> a,
        CompletionToken&& token,
        typename boost::asio::constraint<
            std::is_convertible<ExecutionContext&, boost::asio::execution_context&>::value && std::is_convertible<typename ExecutionContext::executor_type,
                                                                                                                  AwaitableExecutor>::value>::type = 0) {
    return (co_spawn_sw)(ctx.get_executor(),
                         std::move(a),
                         std::forward<CompletionToken>(token));
}

template <
    typename Executor,
    typename F,
    BOOST_ASIO_COMPLETION_TOKEN_FOR(typename boost::asio::detail::awaitable_signature<
                                    typename boost::asio::result_of<F()>::type>::type) CompletionToken>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    CompletionToken,
    typename boost::asio::detail::awaitable_signature<typename boost::asio::result_of<F()>::type>::type)
    co_spawn_sw(
        const Executor& ex,
        F&& f,
        CompletionToken&& token,
        typename boost::asio::constraint<
            boost::asio::is_executor<Executor>::value || boost::asio::execution::is_executor<Executor>::value>::type = 0) {
    return boost::asio::async_initiate<CompletionToken,
                                       typename boost::asio::detail::awaitable_signature<typename boost::asio::result_of<F()>::type>::type>(
        detail::initiate_co_spawn<
            typename boost::asio::result_of<F()>::type::executor_type>(ex),
        token,
        std::forward<F>(f));
}

template <
    typename ExecutionContext,
    typename F,
    BOOST_ASIO_COMPLETION_TOKEN_FOR(typename boost::asio::detail::awaitable_signature<
                                    typename boost::asio::result_of<F()>::type>::type) CompletionToken>
inline BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(
    CompletionToken,
    typename boost::asio::detail::awaitable_signature<typename boost::asio::result_of<F()>::type>::type = 0)
    co_spawn_sw(
        ExecutionContext& ctx, F&& f, CompletionToken&& token,
        typename boost::asio::constraint<
            std::is_convertible<ExecutionContext&, boost::asio::execution_context&>::value>::type) {
    return (co_spawn_sw)(ctx.get_executor(),
                         std::forward<F>(f),
                         std::forward<CompletionToken>(token));
}

}  // namespace silkworm::concurrency
