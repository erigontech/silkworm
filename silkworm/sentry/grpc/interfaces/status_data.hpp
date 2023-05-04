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

#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/eth/status_data.hpp>

namespace silkworm::sentry::grpc::interfaces {

eth::StatusData status_data_from_proto(const ::sentry::StatusData& data, uint8_t eth_version);
::sentry::StatusData proto_status_data_from_status_data(const eth::StatusData& data);

}  // namespace silkworm::sentry::grpc::interfaces
