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

#include <silkworm/infra/grpc/client/bidi_streaming_rpc.hpp>
#include <silkworm/infra/grpc/client/server_streaming_rpc.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

namespace silkworm::db::kv::grpc::client {

using TxRpc = BidiStreamingRpc<&::remote::KV::StubInterface::PrepareAsyncTx>;

using StateChangesRpc = ServerStreamingRpc<&::remote::KV::StubInterface::PrepareAsyncStateChanges>;

}  // namespace silkworm::db::kv::grpc::client
