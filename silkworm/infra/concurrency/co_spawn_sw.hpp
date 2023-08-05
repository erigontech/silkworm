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
#include <type_traits>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/execution_context.hpp>
#include <boost/asio/executor.hpp>
#include <boost/asio/is_executor.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::concurrency::detail {

using boost::asio::awaitable;
using boost::asio::cancellation_state;
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

template <typename Executor>
class initiate_co_spawn {
  public:
    typedef Executor executor_type;

    template <typename OtherExecutor>
    explicit initiate_co_spawn(const OtherExecutor& ex)
        : ex_(ex) {
    }

    executor_type get_executor() const BOOST_ASIO_NOEXCEPT {
        return ex_;
    }

    template <typename Handler, typename F>
    void operator()(Handler&& handler, F&& f) const {
        typedef typename result_of<F()>::type awaitable_type;

        cancellation_state proxy_cancel_state(
            get_associated_cancellation_slot(handler),
            enable_total_cancellation());

        cancellation_state cancel_state(proxy_cancel_state.slot());

        auto a = (co_spawn_entry_point)(static_cast<awaitable_type*>(nullptr),
                                        ex_,
                                        std::forward<F>(f),
                                        std::forward<Handler>(handler));
        awaitable_handler<executor_type, void>(
            std::move(a),
            ex_,
            proxy_cancel_state.slot(),
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
