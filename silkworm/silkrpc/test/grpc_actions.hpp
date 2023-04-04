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

#pragma once

#include <utility>

#include <agrpc/grpc_context.hpp>
#include <agrpc/test.hpp>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc::test {

inline auto finish_with_status(agrpc::GrpcContext& grpc_context, grpc::Status status, bool ok) {
    return [&grpc_context, status, ok](auto&&, ::grpc::Status* status_ptr, void* tag) {
        *status_ptr = status;
        agrpc::process_grpc_tag(grpc_context, tag, ok);
    };
}

inline auto finish_ok(agrpc::GrpcContext& grpc_context) {
    return finish_with_status(grpc_context, grpc::Status::OK, /*ok=*/true);
}

inline auto finish_cancelled(agrpc::GrpcContext& grpc_context) {
    return finish_with_status(grpc_context, grpc::Status::CANCELLED, /*ok=*/true);
}

template <typename Reply>
auto finish_with(agrpc::GrpcContext& grpc_context, Reply&& reply) {
    return [&grpc_context, reply = std::forward<Reply>(reply)](auto* reply_ptr, ::grpc::Status* status,
                                                               void* tag) mutable {
        *reply_ptr = std::move(reply);
        finish_with_status(grpc_context, grpc::Status::OK, /*ok=*/true)(reply_ptr, status, tag);
    };
}

inline auto finish_error(agrpc::GrpcContext& grpc_context) {
    return finish_with_status(grpc_context, grpc::Status::OK, /*ok=*/false);
}

inline auto finish_streaming_with_status(agrpc::GrpcContext& grpc_context, grpc::Status status, bool ok) {
    return [&grpc_context, status, ok](::grpc::Status* status_ptr, void* tag) {
        *status_ptr = status;
        agrpc::process_grpc_tag(grpc_context, tag, ok);
    };
}

inline auto finish_streaming_ok(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, grpc::Status::OK, /*ok=*/true);
}

inline auto finish_streaming_cancelled(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, grpc::Status::CANCELLED, /*ok=*/true);
}

inline auto finish_streaming_aborted(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, grpc::Status{grpc::StatusCode::ABORTED, ""}, /*ok=*/true);
}

inline auto finish_streaming_error(agrpc::GrpcContext& grpc_context) {
    return finish_streaming_with_status(grpc_context, grpc::Status::OK, /*ok=*/false);
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
        agrpc::process_grpc_tag(grpc_context, tag, true);
    };
}

inline auto read_failure(agrpc::GrpcContext& grpc_context) {
    return [&grpc_context](auto*, void* tag) { agrpc::process_grpc_tag(grpc_context, tag, false); };
}

}  // namespace silkworm::rpc::test
