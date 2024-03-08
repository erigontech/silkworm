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

#include <memory>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/server/server_settings.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/sentry/settings.hpp>
#include <silkworm/snapshots/settings.hpp>

namespace silkworm::node {

struct Settings : public NodeSettings {
    log::Settings log_settings;                     // Configuration for the logging facility
    sentry::Settings sentry_settings;               // Configuration for Sentry client + embedded server
    rpc::ServerSettings server_settings;            // Configuration for the gRPC server
    snapshots::SnapshotSettings snapshot_settings;  // Configuration for the database snapshots
};

}  // namespace silkworm::node
