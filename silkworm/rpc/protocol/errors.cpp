// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "errors.hpp"

#include <string>

namespace silkworm::rpc {

// avoid GCC non-virtual-dtor warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"

// NOLINTNEXTLINE(cppcoreguidelines-virtual-class-destructor)
class ProtocolErrorCategory final : public boost::system::error_category {
  public:
    const char* name() const noexcept override {
        return "rpc::ProtocolErrorCategory";
    };

    std::string message(int ev) const override {
        switch (static_cast<ErrorCode>(ev)) {
            case ErrorCode::kParseError:
                return "invalid JSON was received by the server";
            case ErrorCode::kInvalidRequest:
                return "the JSON sent is not a valid Request object";
            case ErrorCode::kMethodNotFound:
                return "the method does not exist / is not available";
            case ErrorCode::kInvalidParams:
                return "invalid method parameter(s)";
            case ErrorCode::kInternalError:
                return "internal JSON-RPC error";
            case ErrorCode::kServerError:
                return "generic client error while processing request";
            case ErrorCode::kUnknownPayload:
                return "payload does not exist / is not available";
            case ErrorCode::kInvalidForkChoiceState:
                return "forkchoice state is invalid / inconsistent";
            case ErrorCode::kInvalidPayloadAttributes:
                return "payload attributes are invalid / inconsistent";
            case ErrorCode::kTooLargeRequest:
                return "number of requested entities is too large";
            default:
                return "unknown error occurred";
        }
    }

    static ProtocolErrorCategory instance;
};

#pragma GCC diagnostic pop

ProtocolErrorCategory ProtocolErrorCategory::instance;

boost::system::error_code to_system_code(ErrorCode e) {
    return {static_cast<int>(e), ProtocolErrorCategory::instance};
}

}  // namespace silkworm::rpc