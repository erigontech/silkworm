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

#include <agrpc/client_rpc.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/interfaces/remote/kv.grpc.pb.h>

namespace silkworm::db::kv::grpc::client {

using TxRpc = boost::asio::use_awaitable_t<>::as_default_on_t<agrpc::ClientRPC<&::remote::KV::StubInterface::PrepareAsyncTx>>;

}  // namespace silkworm::db::kv::grpc::client
