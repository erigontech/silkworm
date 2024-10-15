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