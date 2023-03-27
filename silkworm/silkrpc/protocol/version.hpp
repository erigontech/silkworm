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

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/interfaces/txpool/mining.grpc.pb.h>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>

namespace silkrpc {

struct ProtocolVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
};

constexpr auto KV_SERVICE_API_VERSION = ProtocolVersion{6, 0, 0};
constexpr auto ETHBACKEND_SERVICE_API_VERSION = ProtocolVersion{3, 1, 0};
constexpr auto MINING_SERVICE_API_VERSION = ProtocolVersion{1, 0, 0};
constexpr auto TXPOOL_SERVICE_API_VERSION = ProtocolVersion{1, 0, 0};

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

}  // namespace silkrpc
