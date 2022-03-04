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

#include <silkworm/common/base.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <types/types.pb.h>

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
} // namespace grpc

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {
inline bool operator==(const H160& lhs, const H160& rhs) {
    return lhs.hi().hi() == rhs.hi().hi() &&
        lhs.hi().lo() == rhs.hi().lo() &&
        lhs.lo() == rhs.lo();
}
} // namespace types

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

inline evmc::address address_from_H160(const types::H160& h160) {
    uint64_t hi_hi = h160.hi().hi();
    uint64_t hi_lo = h160.hi().lo();
    uint32_t lo = h160.lo();
    evmc::address address{};
    silkworm::endian::store_big_u64(address.bytes +  0, hi_hi);
    silkworm::endian::store_big_u64(address.bytes +  8, hi_lo);
    silkworm::endian::store_big_u32(address.bytes + 16, lo);
    return address;
}

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_UTIL_HPP_
