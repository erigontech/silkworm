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

#ifndef SILKWORM_RPC_UTIL_HPP_
#define SILKWORM_RPC_UTIL_HPP_

#include <memory>

#include <grpcpp/grpcpp.h>
#include <grpc/support/log.h>

#include <silkworm/common/log.hpp>

// The default gRPC logging function
void gpr_default_log(gpr_log_func_args* args);

//! Define an empty gRPC logging function
static void gpr_no_log(gpr_log_func_args* /*args*/) {
}

//! Define a gRPC logging function delegating to Silkworm logging facility.
static void gpr_silkworm_log(gpr_log_func_args* args) {
    if (args->severity == GPR_LOG_SEVERITY_ERROR) {
        SILK_ERROR << args->message;
    } else if (args->severity == GPR_LOG_SEVERITY_INFO) {
        SILK_INFO << args->message;
    } else { // args->severity == GPR_LOG_SEVERITY_DEBUG
        SILK_DEBUG << args->message;
    }
}

namespace silkworm::rpc {

//! Utility template class using RAII to configure the gRPC logging function for an instance lifetime.
template <void (*F)(gpr_log_func_args*)>
class GrpcLogGuard {
  public:
    explicit GrpcLogGuard() { gpr_set_log_function(F); }
    ~GrpcLogGuard() { gpr_set_log_function(gpr_default_log); }
};

//! Utility class to disable gRPC logging for an instance lifetime.
using GrpcNoLogGuard = GrpcLogGuard<gpr_no_log>;

//! Utility class to map gRPC logging to Silkworm logging for an instance lifetime.
using Grpc2SilkwormLogGuard = GrpcLogGuard<gpr_silkworm_log>;

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_UTIL_HPP_
