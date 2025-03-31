// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "errors.hpp"

#include <string>

namespace silkworm::rpc {

// avoid GCC non-virtual-dtor warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"

// NOLINTNEXTLINE(cppcoreguidelines-virtual-class-destructor)
class GrpcStatusCodeErrorCategory final : public boost::system::error_category {
  public:
    const char* name() const noexcept override {
        return "rpc::GrpcStatusCodeErrorCategory";
    };

    std::string message(int ev) const override {
        switch (static_cast<::grpc::StatusCode>(ev)) {
            case ::grpc::StatusCode::CANCELLED:
                return "the operation was cancelled (typically by the caller)";
            case ::grpc::StatusCode::UNKNOWN:
                return "unknown error";
            case ::grpc::StatusCode::INVALID_ARGUMENT:
                return "client specified an invalid argument";
            case ::grpc::StatusCode::DEADLINE_EXCEEDED:
                return "deadline expired before operation could complete";
            case ::grpc::StatusCode::NOT_FOUND:
                return "some requested entity was not found";
            case ::grpc::StatusCode::ALREADY_EXISTS:
                return "some entity that we attempted to create already exists";
            case ::grpc::StatusCode::PERMISSION_DENIED:
                return "the caller does not have permission to execute the specified operation";
            case ::grpc::StatusCode::UNAUTHENTICATED:
                return "the request does not have valid authentication credentials for the operation";
            case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
                return "some resource has been exhausted";
            case ::grpc::StatusCode::FAILED_PRECONDITION:
                return "operation was rejected because the system is not in a state required for the operation execution";
            case ::grpc::StatusCode::ABORTED:
                return "the operation was aborted";
            case ::grpc::StatusCode::OUT_OF_RANGE:
                return "operation was attempted past the valid range";
            case ::grpc::StatusCode::UNIMPLEMENTED:
                return "operation is not implemented or not supported/enabled in this service";
            case ::grpc::StatusCode::INTERNAL:
                return "internal error";
            case ::grpc::StatusCode::UNAVAILABLE:
                return "the service is currently unavailable";
            case ::grpc::StatusCode::DATA_LOSS:
                return "unrecoverable data loss or corruption";
            default:
                return "unexpected error occurred";
        }
    }

    static GrpcStatusCodeErrorCategory instance;
};

#pragma GCC diagnostic pop

GrpcStatusCodeErrorCategory GrpcStatusCodeErrorCategory::instance;

boost::system::error_code to_system_code(::grpc::StatusCode status_code) {
    return {static_cast<int>(status_code), GrpcStatusCodeErrorCategory::instance};
}

}  // namespace silkworm::rpc
