// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <agrpc/detail/forward.hpp>

#include <silkworm/sentry/api/common/sentry_client.hpp>

namespace silkworm::sentry::grpc::client {

class SentryClientImpl;

class SentryClient : public api::SentryClient {
  public:
    explicit SentryClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context);
    ~SentryClient() override;

    SentryClient(SentryClient&&) = default;
    SentryClient& operator=(SentryClient&&) = default;

    Task<std::shared_ptr<api::Service>> service() override;

    bool is_ready() override;
    void on_disconnect(std::function<Task<void>()> callback) override;
    Task<void> reconnect() override;

  private:
    std::shared_ptr<SentryClientImpl> p_impl_;
};

}  // namespace silkworm::sentry::grpc::client
