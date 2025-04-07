// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
