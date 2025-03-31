// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc::test {

inline auto exception_has_grpc_status_code(::grpc::StatusCode status_code) {
    return Catch::Matchers::Predicate<const boost::system::system_error&>(
        [status_code](auto& e) { return std::error_code(e.code()).value() == status_code; });
}

inline auto exception_has_aborted_grpc_status_code() {
    return test::exception_has_grpc_status_code(::grpc::StatusCode::ABORTED);
}

inline auto exception_has_cancelled_grpc_status_code() {
    return test::exception_has_grpc_status_code(::grpc::StatusCode::CANCELLED);
}

inline auto exception_has_unknown_grpc_status_code() {
    return test::exception_has_grpc_status_code(::grpc::StatusCode::UNKNOWN);
}

}  // namespace silkworm::rpc::test
