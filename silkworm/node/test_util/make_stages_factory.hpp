// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>

#include "../common/node_settings.hpp"
#include "../stagedsync/execution_pipeline.hpp"
#include "../stagedsync/stages/stage_bodies_factory.hpp"

namespace silkworm::stagedsync::test_util {

BodiesStageFactory make_bodies_stage_factory(const ChainConfig& chain_config, db::DataModelFactory data_model_factory);
StageContainerFactory make_stages_factory(const NodeSettings& node_settings, db::DataModelFactory data_model_factory);

}  // namespace silkworm::stagedsync::test_util
