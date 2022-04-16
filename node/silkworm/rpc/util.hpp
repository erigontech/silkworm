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
#include <string>

#include <evmc/evmc.hpp>
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
    } else { // args->severity == GPR_LOG_SEVERITY_DEBUG
        SILK_DEBUG << log_message;
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

//! Convert internal RPC H160 type instance to evmc::address.
inline evmc::address address_from_H160(const types::H160& h160) {
    uint64_t hi_hi = h160.hi().hi();
    uint64_t hi_lo = h160.hi().lo();
    uint32_t lo = h160.lo();
    evmc::address address;
    endian::store_big_u64(address.bytes +  0, hi_hi);
    endian::store_big_u64(address.bytes +  8, hi_lo);
    endian::store_big_u32(address.bytes + 16, lo);
    return address;
}

//! Convert internal RPC H256 type instance to evmc::bytes32.
inline evmc::bytes32 bytes32_from_H256(const types::H256& h256) {
    uint64_t hi_hi = h256.hi().hi();
    uint64_t hi_lo = h256.hi().lo();
    uint64_t lo_hi = h256.lo().hi();
    uint64_t lo_lo = h256.lo().lo();
    evmc::bytes32 b32;
    endian::store_big_u64(b32.bytes + 0, hi_hi);
    endian::store_big_u64(b32.bytes + 8, hi_lo);
    endian::store_big_u64(b32.bytes + 16, lo_hi);
    endian::store_big_u64(b32.bytes + 24, lo_lo);
    return b32;
}

//! Convert evmc::address to internal RPC H160 type instance.
inline types::H160* new_H160_from_address(const evmc::address& address) {
    types::H160* h160 = new types::H160{};
    types::H128* hi = new types::H128{};
    hi->set_hi(endian::load_big_u64(address.bytes));
    hi->set_lo(endian::load_big_u64(address.bytes + 8));
    h160->set_allocated_hi(hi); // takes ownership
    h160->set_lo(endian::load_big_u32(address.bytes + 16));
    return h160;
}

//! Convert evmc::bytes32 to internal RPC H256 type instance.
inline types::H256* new_H256_from_hash(const evmc::bytes32& hash) {
    types::H128* hi = new types::H128{};
    types::H128* lo = new types::H128{};
    hi->set_hi(endian::load_big_u64(hash.bytes + 0));
    hi->set_lo(endian::load_big_u64(hash.bytes + 8));
    lo->set_hi(endian::load_big_u64(hash.bytes + 16));
    lo->set_lo(endian::load_big_u64(hash.bytes + 24));

    types::H256* h256 = new types::H256{};
    h256->set_allocated_hi(hi); // takes ownership
    h256->set_allocated_lo(lo); // takes ownership
    return h256;
}

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_UTIL_HPP_
