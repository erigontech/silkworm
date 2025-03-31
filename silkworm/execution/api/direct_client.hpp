// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include "../api/client.hpp"
#include "../api/direct_service.hpp"

namespace silkworm::execution::api {

struct DirectClient : public api::Client {
    explicit DirectClient(std::shared_ptr<DirectService> direct_service);
    ~DirectClient() override = default;

    std::shared_ptr<api::Service> service() override;

  private:
    std::shared_ptr<DirectService> direct_service_;
};

}  // namespace silkworm::execution::api
