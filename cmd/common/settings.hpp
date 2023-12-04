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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/settings.hpp>
#include <silkworm/node/snapshot/settings.hpp>
#include <silkworm/rpc/settings.hpp>
#include <silkworm/sentry/settings.hpp>

namespace silkworm::cmd::common {

//! The overall settings
struct SilkwormSettings {
    log::Settings log_settings;
    node::Settings node_settings;
    sentry::Settings sentry_settings;
    rpc::DaemonSettings rpcdaemon_settings;
    bool force_pow{false};  // TODO(canepat) remove when PoS sync works
};

}  // namespace silkworm::cmd::common
