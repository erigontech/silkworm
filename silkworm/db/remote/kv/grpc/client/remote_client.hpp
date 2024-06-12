/*
   Copyright 2024 The Silkworm Authors

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

#include <memory>

#include <agrpc/detail/forward.hpp>

#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "../../api/client.hpp"
#include "../../api/service.hpp"

namespace silkworm::kv::grpc::client {

class RemoteClientImpl;

struct RemoteClient : public api::Client {
    RemoteClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context);
    RemoteClient(std::unique_ptr<::remote::KV::StubInterface> stub, agrpc::GrpcContext& grpc_context);
    ~RemoteClient() override;

    std::shared_ptr<api::Service> service() override;

  private:
    std::shared_ptr<RemoteClientImpl> p_impl_;
};

}  // namespace silkworm::kv::grpc::client
