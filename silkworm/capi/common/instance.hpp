// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include "common_component.hpp"

namespace silkworm::db::capi {
struct Component;
}

namespace silkworm::rpc {
class Daemon;
}

namespace silkworm::sentry::capi {
struct Component;
}

namespace capi_todo {

struct SilkwormInstance {
    silkworm::capi::CommonComponent common;
    std::unique_ptr<silkworm::db::capi::Component> db;
    std::unique_ptr<silkworm::rpc::Daemon> rpcdaemon;
    std::unique_ptr<silkworm::sentry::capi::Component> sentry;

    SilkwormInstance();
    ~SilkwormInstance();
};

}  // namespace capi_todo