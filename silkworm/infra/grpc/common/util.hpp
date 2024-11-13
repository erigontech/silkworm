/*
   Copyright 2022 The Silkworm Authors

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

#include <ostream>
#include <string>

#include <grpc/support/log.h>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/log.hpp>

namespace grpc {

// operator== overloading for grpc::Status is *NOT* present in gRPC library
inline bool operator==(const Status& lhs, const Status& rhs) {
    return lhs.error_code() == rhs.error_code() &&
           lhs.error_message() == rhs.error_message() &&
           lhs.error_details() == rhs.error_details();
}

// operator<< overloading for grpc::Status is *NOT* present in gRPC library
inline std::ostream& operator<<(std::ostream& out, const Status& status) {
    out << "status=" << (status.ok() ? "OK" : "KO");
    if (!status.ok()) {
        out << " error_code=" << status.error_code()
            << " error_message=" << status.error_message()
            << " error_details=" << status.error_details();
    }
    return out;
}

}  // namespace grpc

// The default gRPC logging function
void gpr_default_log(gpr_log_func_args* args);

//! Define an empty gRPC logging function
inline void gpr_no_log(gpr_log_func_args* /*args*/) {
}

//! Define a gRPC logging function delegating to Silkworm logging facility.
inline void gpr_silkworm_log(gpr_log_func_args* args) {
    std::string log_message{"gRPC: "};
    log_message.append(args->message);
    if (args->severity == GPR_LOG_SEVERITY_ERROR) {
        log_message.append(" ");
        log_message.append(args->file);
        log_message.append(":");
        log_message.append(std::to_string(args->line));
        SILK_ERROR << log_message;
    } else if (args->severity == GPR_LOG_SEVERITY_INFO) {
        SILK_INFO << log_message;
    } else {  // args->severity == GPR_LOG_SEVERITY_DEBUG
        SILK_DEBUG << log_message;
    }
}

namespace silkworm::rpc {

//! Utility template class using RAII to configure the gRPC logging function for an instance lifetime.
template <void (*F)(gpr_log_func_args*)>
class GrpcLogGuard {
  public:
    explicit GrpcLogGuard() { gpr_set_log_function(F); }
    ~GrpcLogGuard() { gpr_set_log_function(gpr_silkworm_log); }
};

//! Utility class to disable gRPC logging for an instance lifetime.
using GrpcNoLogGuard = GrpcLogGuard<gpr_no_log>;

//! Utility class to map gRPC logging to Silkworm logging for an instance lifetime.
using Grpc2SilkwormLogGuard = GrpcLogGuard<gpr_silkworm_log>;

}  // namespace silkworm::rpc
