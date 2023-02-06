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

#include "awaitable_wait_for_all.hpp"

#include <stdexcept>

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

namespace silkworm::sentry::common::awaitable_wait_for_all::detail {

static bool is_operation_cancelled_error(const std::exception_ptr& ex_ptr) {
    try {
        std::rethrow_exception(ex_ptr);
    } catch (const boost::system::system_error& e) {
        return (e.code() == boost::system::errc::operation_canceled);
    } catch (...) {
        return false;
    }
}

void rethrow_exceptions(const std::exception_ptr& ex0, const std::exception_ptr& ex1, const std::array<std::size_t, 2>& order) {
    // no exceptions
    if (!ex0 && !ex1)
        return;

    // only 1 exception
    if (!ex0)
        std::rethrow_exception(ex1);
    if (!ex1)
        std::rethrow_exception(ex0);

    // 2 exceptions, but one of them is an expected operation_canceled caused by aborting a pending branch
    if (is_operation_cancelled_error(ex0))
        std::rethrow_exception(ex1);
    if (is_operation_cancelled_error(ex1))
        std::rethrow_exception(ex0);

    // 2 unexpected exceptions
    // This is possible if operation_canceled is handled inside a pending operation,
    // but the catch block throws a different error.
    // ex0 was first
    if (order[0] == 0) {
        try {
            std::rethrow_exception(ex1);
        } catch (const std::runtime_error& ex1_ref) {
            try {
                std::rethrow_exception(ex0);
            } catch (...) {
                std::throw_with_nested(ex1_ref);
            }
        }
    }
    // ex1 was first
    else {
        try {
            std::rethrow_exception(ex0);
        } catch (const std::runtime_error& ex0_ref) {
            try {
                std::rethrow_exception(ex1);
            } catch (...) {
                std::throw_with_nested(ex0_ref);
            }
        }
    }
}

}  // namespace silkworm::sentry::common::awaitable_wait_for_all::detail
