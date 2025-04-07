// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "shared_service.hpp"

#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("SharedService", "[silkworm][infra][concurrency][services]") {
    struct Integer {
        explicit Integer(int value) : value_(value) {}
        int value() const { return value_; }

      private:
        int value_{0};
    };
    boost::asio::io_context ioc1;
    boost::asio::io_context ioc2;

    SECTION("register service") {
        CHECK(!use_shared_service<Integer>(ioc1));
        CHECK(!use_shared_service<Integer>(ioc2));
        CHECK_THROWS_AS(must_use_shared_service<Integer>(ioc1), std::logic_error);
        CHECK_THROWS_AS(must_use_shared_service<Integer>(ioc2), std::logic_error);
        auto shared_integer = std::make_shared<Integer>(1);
        CHECK_NOTHROW(add_shared_service<Integer>(ioc1, shared_integer));
        CHECK_NOTHROW(add_shared_service<Integer>(ioc2, shared_integer));
        CHECK(use_shared_service<Integer>(ioc1)->value() == 1);
        CHECK(use_shared_service<Integer>(ioc2)->value() == 1);
        CHECK(must_use_shared_service<Integer>(ioc1)->value() == 1);
        CHECK(must_use_shared_service<Integer>(ioc2)->value() == 1);
    }
    SECTION("register service twice") {
        CHECK(!use_shared_service<Integer>(ioc1));
        CHECK(!use_shared_service<Integer>(ioc2));
        CHECK_THROWS_AS(must_use_shared_service<Integer>(ioc1), std::logic_error);
        CHECK_THROWS_AS(must_use_shared_service<Integer>(ioc2), std::logic_error);
        auto shared_integer_1 = std::make_shared<Integer>(1);
        auto shared_integer_2 = std::make_shared<Integer>(2);
        CHECK_NOTHROW(add_shared_service<Integer>(ioc1, shared_integer_1));
        CHECK_NOTHROW(add_shared_service<Integer>(ioc2, shared_integer_1));
        CHECK(use_shared_service<Integer>(ioc1)->value() == 1);
        CHECK(use_shared_service<Integer>(ioc2)->value() == 1);
        CHECK(must_use_shared_service<Integer>(ioc1)->value() == 1);
        CHECK(must_use_shared_service<Integer>(ioc2)->value() == 1);
        CHECK_NOTHROW(add_shared_service<Integer>(ioc1, shared_integer_2));
        CHECK_NOTHROW(add_shared_service<Integer>(ioc2, shared_integer_2));
        CHECK(use_shared_service<Integer>(ioc1)->value() == 2);
        CHECK(use_shared_service<Integer>(ioc2)->value() == 2);
        CHECK(must_use_shared_service<Integer>(ioc1)->value() == 2);
        CHECK(must_use_shared_service<Integer>(ioc2)->value() == 2);
    }
}

}  // namespace silkworm
