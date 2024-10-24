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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>

#include "../common/node_settings.hpp"
#include "../stagedsync/execution_pipeline.hpp"
#include "../stagedsync/stages/stage_bodies_factory.hpp"

namespace silkworm::stagedsync::test_util {

BodiesStageFactory make_bodies_stage_factory(const ChainConfig& chain_config, db::DataModelFactory data_model_factory);
StageContainerFactory make_stages_factory(const NodeSettings& node_settings, db::DataModelFactory data_model_factory);

}  // namespace silkworm::stagedsync::test_util
