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

#include "eth_version.hpp"

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;

uint8_t eth_version_from_protocol(proto::Protocol protocol) {
    static_assert(proto::Protocol_MIN == proto::Protocol::ETH65);
    return static_cast<uint8_t>(protocol) + 65;
}

proto::Protocol protocol_from_eth_version(uint8_t version) {
    static_assert(proto::Protocol_MIN == proto::Protocol::ETH65);
    return static_cast<proto::Protocol>(version - 65);
}

}  // namespace silkworm::sentry::grpc::interfaces
