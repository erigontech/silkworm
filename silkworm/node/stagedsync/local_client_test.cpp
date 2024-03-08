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

#include "local_client.hpp"

#include <catch2/catch.hpp>

#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/stagedsync/server.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

namespace silkworm::execution {

TEST_CASE("execution::LocalClient") {
    test_util::SetLogVerbosityGuard log_guard(log::Level::kNone);
    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
    db::RWAccess db_access{context.env()};

    Server embedded_server{node_settings, db_access};
    CHECK_NOTHROW(LocalClient{embedded_server});
}

}  // namespace silkworm::execution
