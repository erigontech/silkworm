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

#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/api/common/node_info.hpp>

namespace silkworm::sentry::grpc::interfaces {

api::NodeInfo node_info_from_proto_node_info(const types::NodeInfoReply& info);
types::NodeInfoReply proto_node_info_from_node_info(const api::NodeInfo& info);

}  // namespace silkworm::sentry::grpc::interfaces
