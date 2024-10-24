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

#include <silkworm/db/access_layer.hpp>
#include <silkworm/node/common/node_settings.hpp>

#include "execution_pipeline.hpp"
#include "stages/stage_bodies_factory.hpp"

namespace silkworm::stagedsync {

class StagesFactoryImpl {
  public:
    StagesFactoryImpl(
        const NodeSettings& settings,
        db::DataModelFactory data_model_factory,
        BodiesStageFactory bodies_stage_factory)
        : settings_{settings},
          data_model_factory_{std::move(data_model_factory)},
          bodies_stage_factory_{std::move(bodies_stage_factory)} {}

    static StageContainerFactory to_factory(StagesFactoryImpl instance);

  private:
    StageContainer make(SyncContext& sync_context) const;

    const NodeSettings& settings_;
    db::DataModelFactory data_model_factory_;
    BodiesStageFactory bodies_stage_factory_;
};

}  // namespace silkworm::stagedsync
