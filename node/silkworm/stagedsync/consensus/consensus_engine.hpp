/*
Copyright 2022 The Silkworm Authors

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

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>

namespace silkworm::stagedsync {

class ConsensusEngine : public ActiveComponent {
  public:
    ConsensusEngine(const NodeSettings&, const db::ROAccess&, ExecutionEngine&);

    void execution_loop() final;           /*[[long_running]]*/

  private:
    const NodeSettings& node_settings_;
    db::ROAccess db_access_;
    ExecutionEngine& exec_engine_;
};

}  // namespace silkworm::stagedsync
