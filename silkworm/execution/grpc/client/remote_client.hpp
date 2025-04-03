// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <agrpc/detail/forward.hpp>

#include "../../api/client.hpp"
#include "../../api/service.hpp"

namespace silkworm::execution::grpc::client {

class RemoteClientImpl;

struct RemoteClient : public api::Client {
    RemoteClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context);
    ~RemoteClient() override;

    std::shared_ptr<api::Service> service() override;

  private:
    std::shared_ptr<RemoteClientImpl> p_impl_;
};

}  // namespace silkworm::execution::grpc::client
