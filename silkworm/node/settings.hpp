// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/db/datastore/snapshots/snapshot_settings.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/server/server_settings.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/rpc/settings.hpp>
#include <silkworm/sentry/settings.hpp>

namespace silkworm::node {

struct Settings {
    log::Settings log_settings;                     // Configuration for the logging facility
    NodeSettings node_settings;                     // Configuration for the node
    rpc::DaemonSettings rpcdaemon_settings;         // Configuration for the RPC daemon
    sentry::Settings sentry_settings;               // Configuration for Sentry client + embedded server
    rpc::ServerSettings server_settings;            // Configuration for the gRPC server
    snapshots::SnapshotSettings snapshot_settings;  // Configuration for the database snapshots
};

}  // namespace silkworm::node
