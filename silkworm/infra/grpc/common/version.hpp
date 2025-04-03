// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/interfaces/txpool/mining.grpc.pb.h>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>

namespace silkworm::rpc {

struct ProtocolVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
};

inline constexpr ProtocolVersion kKvServiceApiVersion{7, 0, 0};
inline constexpr ProtocolVersion kEthBackEndServiceApiVersion{3, 3, 0};
inline constexpr ProtocolVersion kMiningServiceApiVersion{1, 0, 0};
inline constexpr ProtocolVersion kTxPoolServiceApiVersion{1, 0, 0};

std::ostream& operator<<(std::ostream& out, const ProtocolVersion& v);

struct ProtocolVersionResult {
    bool compatible;
    std::string result;
};

ProtocolVersionResult wait_for_kv_protocol_check(const std::unique_ptr<::remote::KV::StubInterface>& stub);
ProtocolVersionResult wait_for_kv_protocol_check(const std::shared_ptr<grpc::Channel>& channel);

ProtocolVersionResult wait_for_ethbackend_protocol_check(const std::unique_ptr<::remote::ETHBACKEND::StubInterface>& stub);
ProtocolVersionResult wait_for_ethbackend_protocol_check(const std::shared_ptr<grpc::Channel>& channel);

ProtocolVersionResult wait_for_mining_protocol_check(const std::unique_ptr<::txpool::Mining::StubInterface>& stub);
ProtocolVersionResult wait_for_mining_protocol_check(const std::shared_ptr<grpc::Channel>& channel);

ProtocolVersionResult wait_for_txpool_protocol_check(const std::unique_ptr<::txpool::Txpool::StubInterface>& stub);
ProtocolVersionResult wait_for_txpool_protocol_check(const std::shared_ptr<grpc::Channel>& channel);

}  // namespace silkworm::rpc
