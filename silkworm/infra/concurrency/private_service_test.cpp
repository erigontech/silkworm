// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "private_service.hpp"

#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("PrivateService", "[silkworm][infra][concurrency][services]") {
    struct Integer {
        explicit Integer(int value) : value_(value) {}
        int value() const { return value_; }

      private:
        int value_{0};
    };
    boost::asio::io_context ioc;

    SECTION("register service") {
        CHECK(!use_private_service<Integer>(ioc));
        CHECK_THROWS_AS(must_use_private_service<Integer>(ioc), std::logic_error);
        CHECK_NOTHROW(add_private_service<Integer>(ioc, std::make_unique<Integer>(1)));
        CHECK(use_private_service<Integer>(ioc)->value() == 1);
        CHECK(must_use_private_service<Integer>(ioc)->value() == 1);
    }
    SECTION("register service twice") {
        CHECK(!use_private_service<Integer>(ioc));
        CHECK_THROWS_AS(must_use_private_service<Integer>(ioc), std::logic_error);
        CHECK_NOTHROW(add_private_service<Integer>(ioc, std::make_unique<Integer>(1)));
        CHECK(use_private_service<Integer>(ioc)->value() == 1);
        CHECK(must_use_private_service<Integer>(ioc)->value() == 1);
        CHECK_NOTHROW(add_private_service<Integer>(ioc, std::make_unique<Integer>(2)));
        CHECK(use_private_service<Integer>(ioc)->value() == 2);
        CHECK(must_use_private_service<Integer>(ioc)->value() == 2);
    }
    SECTION("register and lookup with same type") {
        class A {};
        class B : public A {};
        CHECK(!use_private_service<A>(ioc));
        CHECK(!use_private_service<B>(ioc));
        CHECK_THROWS_AS(must_use_private_service<A>(ioc), std::logic_error);
        CHECK_THROWS_AS(must_use_private_service<B>(ioc), std::logic_error);
        CHECK_NOTHROW(add_private_service(ioc, std::make_unique<B>()));
        CHECK(!use_private_service<A>(ioc));
        CHECK_THROWS_AS(must_use_private_service<A>(ioc), std::logic_error);
        CHECK(use_private_service<B>(ioc));
        CHECK(must_use_private_service<B>(ioc));
        CHECK_NOTHROW(add_private_service<A>(ioc, std::make_unique<B>()));
        CHECK(use_private_service<A>(ioc));
        CHECK(must_use_private_service<A>(ioc));
    }
}

}  // namespace silkworm
