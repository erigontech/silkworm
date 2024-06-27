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

#include "direct_client.hpp"

namespace silkworm::db::kv::api {

DirectClient::DirectClient(std::shared_ptr<DirectService> direct_service)
    : direct_service_(std::move(direct_service)) {}

std::shared_ptr<api::Service> DirectClient::service() {
    return direct_service_;
}

}  // namespace silkworm::db::kv::api
