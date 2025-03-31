// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "util.hpp"

#include <absl/log/absl_log.h>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE

TEST_CASE("print grpc::Status", "[silkworm][rpc][util]") {
    CHECK_NOTHROW(test_util::null_stream() << grpc::Status::OK);
    CHECK_NOTHROW(test_util::null_stream() << grpc::Status::CANCELLED);
}

TEST_CASE("compare grpc::Status", "[silkworm][rpc][util]") {
    CHECK(grpc::Status::OK == grpc::Status::OK);
    CHECK(!(grpc::Status::OK == grpc::Status::CANCELLED));

    grpc::Status status1{grpc::StatusCode::INTERNAL, "error"};
    grpc::Status status2{grpc::StatusCode::INTERNAL, "err"};
    CHECK(!(status1 == status2));

    grpc::Status status3{grpc::StatusCode::INTERNAL, "error", "details"};
    grpc::Status status4{grpc::StatusCode::INTERNAL, "error", ""};
    CHECK(!(status3 == status4));
}

#ifdef SILKWORM_TEST_SKIP
TEST_CASE("AbseilLogGuard", "[silkworm][rpc][util]") {
    struct TestLogSink : public absl::LogSink {
        bool message_sent{};
        ~TestLogSink() override = default;
        void Send(const absl::LogEntry&) override {
            message_sent = true;
        }
    };

    log::Settings settings{
        .log_nocolor = true,
        .log_verbosity = log::Level::kInfo,
    };
    log::init(settings);

    log::AbseilLogGuard<TestLogSink> log_guard;
    CHECK_FALSE(log_guard.sink().message_sent);
    ABSL_LOG(INFO) << "message for TestLogSink";
    CHECK(log_guard.sink().message_sent);
}
#endif  // SILKWORM_TEST_SKIP

#ifdef SILKWORM_TEST_SKIP
TEST_CASE("AbseilToSilkwormLogSink", "[silkworm][rpc][util]") {
    log::Settings settings{
        .log_nocolor = true,
        .log_verbosity = log::Level::kTrace,
    };
    log::init(settings);

    // ABSL_LOG(FATAL) << "ABSL_LOG(FATAL)";
    ABSL_LOG(ERROR) << "ABSL_LOG(ERROR) @ Level::kError";
    ABSL_LOG(WARNING) << "ABSL_LOG(WARN) @ Level::kWarn";
    ABSL_LOG(INFO) << "ABSL_LOG(INFO) @ Level::kInfo";
    ABSL_VLOG(2) << "ABSL_VLOG(2) @ Level::kDebug";
    ABSL_VLOG(4) << "ABSL_VLOG(4) @ Level::kTrace";
}
#endif  // SILKWORM_TEST_SKIP

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
