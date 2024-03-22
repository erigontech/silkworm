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

#include <cstdint>

#include <boost/system/system_error.hpp>

namespace silkworm::rpc {

enum ErrorCode : int64_t {
    /** Generic JSON-RPC API errors **/
    kParseError = -32700,      // Invalid JSON was received by the server
    kInvalidRequest = -32600,  // The JSON sent is not a valid Request object
    kMethodNotFound = -32601,  // The method does not exist / is not available
    kInvalidParams = -32602,   // Invalid method parameter(s)
    kInternalError = -32603,   // Internal JSON-RPC error
    kServerError = -32000,     // Generic client error while processing request

    /** Engine API errors **/
    kUnknownPayload = -38001,            // Payload does not exist / is not available
    kInvalidForkChoiceState = -38002,    // Forkchoice state is invalid / inconsistent
    kInvalidPayloadAttributes = -38003,  // Payload attributes are invalid / inconsistent
    kTooLargeRequest = -38004,           // Number of requested entities is too large
    kUnsupportedFork = -38005,           // Invalid API version for the current fork
};

// To raise a boost::system::system_error exception:
//    throw boost::system::system_error{rpc::to_system_code(rpc::ErrorCode::kSomething)};
boost::system::error_code to_system_code(ErrorCode e);

}  // namespace silkworm::rpc
