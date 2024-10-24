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

#include "make_stages_factory.hpp"

#include "../stagedsync/stages/stage_bodies.hpp"
#include "../stagedsync/stages_factory_impl.hpp"

namespace silkworm::stagedsync::test_util {

BodiesStageFactory make_bodies_stage_factory(const ChainConfig& chain_config, db::DataModelFactory data_model_factory) {
    return [chain_config, data_model_factory = std::move(data_model_factory)](SyncContext* sync_context) {
        return std::make_unique<BodiesStage>(
            sync_context,
            chain_config,
            data_model_factory,
            [] { return 0; });
    };
};

StageContainerFactory make_stages_factory(const NodeSettings& node_settings, db::DataModelFactory data_model_factory) {
    auto bodies_stage_factory = make_bodies_stage_factory(*node_settings.chain_config, data_model_factory);
    return StagesFactoryImpl::to_factory({
        node_settings,
        std::move(data_model_factory),
        std::move(bodies_stage_factory),
    });
}

}  // namespace silkworm::stagedsync::test_util
