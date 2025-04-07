// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
