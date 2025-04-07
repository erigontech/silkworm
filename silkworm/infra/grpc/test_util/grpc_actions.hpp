// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <utility>

#include <agrpc/grpc_context.hpp>
#include <agrpc/test.hpp>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc::test {

inline auto finish_with_status(agrpc::GrpcContext& grpc_context, const ::grpc::Status& status, bool ok) {
    return [&grpc_context, status, ok](auto&&, ::grpc::Status* status_ptr, void* tag) {
        *status_ptr = status;
        agrpc::process_grpc_tag(grpc_context, tag, ok);
    };
}

inline auto finish_ok(agrpc::GrpcContext& grpc_context) {
    return finish_with_status(grpc_context, ::grpc::Status::OK, /*ok=*/true);
}

inline auto finish_cancelled(agrpc::GrpcContext& grpc_context) {
    return finish_with_status(grpc_context, ::grpc::Status::CANCELLED, /*ok=*/true);
}

template <typename Reply>
auto finish_with(agrpc::GrpcContext& grpc_context, Reply&& reply) {
    return [&grpc_context, reply = std::forward<Reply>(reply)](auto* reply_ptr, ::grpc::Status* status,
                                                               void* tag) mutable {
        *reply_ptr = std::move(reply);
        finish_with_status(grpc_context, ::grpc::Status::OK, /*ok=*/true)(reply_ptr, status, tag);
    };
}

inline auto finish_error(agrpc::GrpcContext& grpc_context, const ::grpc::Status& status) {
    return finish_with_status(grpc_context, status, /*ok=*/false);
}

template <typename Reply>
auto finish_error(agrpc::GrpcContext& grpc_context, ::grpc::Status&& status, Reply&& reply) {
    return [&grpc_context, status = std::move(status), reply = std::forward<Reply>(reply)](auto* reply_ptr,
                                                                                           ::grpc::Status* status_ptr,
                                                                                           void* tag) mutable {
        *reply_ptr = std::move(reply);
        finish_with_status(grpc_context, status, /*ok=*/false)(reply_ptr, status_ptr, tag);
    };
}

template <typename Reply>
auto finish_error_aborted(agrpc::GrpcContext& grpc_context, Reply&& reply) {
    return finish_error(grpc_context, ::grpc::Status{::grpc::StatusCode::ABORTED, "internal failure"}, std::forward<Reply>(reply));
}

template <typename Reply>
auto finish_error_cancelled(agrpc::GrpcContext& grpc_context, Reply&& reply) {
    return finish_error(grpc_context, ::grpc::Status::CANCELLED, std::forward<Reply>(reply));
}

inline auto finish_streaming_with_status(agrpc::GrpcContext& grpc_context, const ::grpc::Status& status, bool ok) {
    return [&grpc_context, status, ok](::grpc::Status* status_ptr, void* tag) {
        *status_ptr = status;
        agrpc::process_grpc_tag(grpc_context, tag, ok);
    };
}

inline auto finish_streaming_ok(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, ::grpc::Status::OK, /*ok=*/true);
}

inline auto finish_streaming_cancelled(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, ::grpc::Status::CANCELLED, /*ok=*/true);
}

inline auto finish_streaming_aborted(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, ::grpc::Status{::grpc::StatusCode::ABORTED, ""}, /*ok=*/true);
}

inline auto finish_streaming_unavailable(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, ::grpc::Status{::grpc::StatusCode::UNAVAILABLE, ""}, /*ok=*/true);
}

inline auto finish_streaming_error(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, ::grpc::Status{::grpc::StatusCode::UNKNOWN, ""}, /*ok=*/false);
}

inline auto write(agrpc::GrpcContext& grpc_context, bool ok) {
    return [&grpc_context, ok](auto&&, void* tag) { agrpc::process_grpc_tag(grpc_context, tag, ok); };
}

inline auto write_success(agrpc::GrpcContext& grpc_context) { return write(grpc_context, true); }

inline auto write_failure(agrpc::GrpcContext& grpc_context) { return write(grpc_context, false); }

inline auto writes_done(agrpc::GrpcContext& grpc_context, bool ok) {
    return [&grpc_context, ok](void* tag) { agrpc::process_grpc_tag(grpc_context, tag, ok); };
}

inline auto writes_done_success(agrpc::GrpcContext& grpc_context) { return writes_done(grpc_context, true); }

inline auto writes_done_failure(agrpc::GrpcContext& grpc_context) { return writes_done(grpc_context, false); }

template <typename Reply>
auto read_success_with(agrpc::GrpcContext& grpc_context, Reply&& reply) {
    return [&grpc_context, reply = std::forward<Reply>(reply)](auto* reply_ptr, void* tag) mutable {
        *reply_ptr = std::move(reply);
        agrpc::process_grpc_tag(grpc_context, tag, /*ok=*/true);
    };
}

inline auto read_failure(agrpc::GrpcContext& grpc_context) {
    return [&grpc_context](auto*, void* tag) { agrpc::process_grpc_tag(grpc_context, tag, /*ok=*/false); };
}

}  // namespace silkworm::rpc::test
