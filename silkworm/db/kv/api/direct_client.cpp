// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "direct_client.hpp"

namespace silkworm::db::kv::api {

DirectClient::DirectClient(std::shared_ptr<DirectService> direct_service)
    : direct_service_(std::move(direct_service)) {}

std::shared_ptr<api::Service> DirectClient::service() {
    return direct_service_;
}

}  // namespace silkworm::db::kv::api
