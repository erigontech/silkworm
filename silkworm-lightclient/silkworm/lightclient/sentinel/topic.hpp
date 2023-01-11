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

#include <string>

namespace silkworm::cl::sentinel {

constexpr auto kMaximumRequestClientUpdates{128};

const std::string kProtocolPrefix{"/eth2/beacon_chain/req"};
const std::string kEncodingProtocol{"/ssz_snappy"};

// Request and Response versions
const std::string kSchema1{"/1"};
const std::string kSchema2{"/2"};

// Request and Response topics
const std::string kMetadataTopic{"/metadata"};
const std::string kPingTopic{"/ping"};
const std::string kStatusTopic{"/status"};
const std::string kGoodbyeTopic{"/goodbye"};
const std::string kBeaconBlocksByRangeTopic{"/beacon_blocks_by_range"};
const std::string kBeaconBlocksByRootTopic{"/beacon_blocks_by_root"};
const std::string kLightClientFinalityUpdateTopic{"/light_client_finality_update"};
const std::string kLightClientOptimisticUpdateTopic{"/light_client_optimistic_update"};
const std::string kLightClientBootstrapTopic{"/light_client_bootstrap"};
const std::string kLightClientUpdatesByRangeTopic{"/light_client_updates_by_range"};

// Request and Response protocol ids
const std::string kPingProtocolV1{kProtocolPrefix + kPingTopic + kSchema1 + kEncodingProtocol};
const std::string kGoodbyeProtocolV1{kProtocolPrefix + kGoodbyeTopic + kSchema1 + kEncodingProtocol};

const std::string kMetadataProtocolV1{kProtocolPrefix + kMetadataTopic + kSchema1 + kEncodingProtocol};
const std::string kMetadataProtocolV2{kProtocolPrefix + kMetadataTopic + kSchema2 + kEncodingProtocol};

const std::string kStatusProtocolV1{kProtocolPrefix + kStatusTopic + kSchema1 + kEncodingProtocol};

const std::string kBeaconBlocksByRangeProtocolV1{kProtocolPrefix + kBeaconBlocksByRangeTopic + kSchema1 + kEncodingProtocol};
const std::string kBeaconBlocksByRangeProtocolV2{kProtocolPrefix + kBeaconBlocksByRangeTopic + kSchema2 + kEncodingProtocol};

const std::string kBeaconBlocksByRootProtocolV1{kProtocolPrefix + kBeaconBlocksByRootTopic + kSchema1 + kEncodingProtocol};
const std::string kBeaconBlocksByRootProtocolV2{kProtocolPrefix + kBeaconBlocksByRootTopic + kSchema2 + kEncodingProtocol};

const std::string kLightClientFinalityUpdateV1{kProtocolPrefix + kLightClientFinalityUpdateTopic + kSchema1 + kEncodingProtocol};
const std::string kLightClientOptimisticUpdateV1{kProtocolPrefix + kLightClientOptimisticUpdateTopic + kSchema1 + kEncodingProtocol};
const std::string kLightClientBootstrapV1{kProtocolPrefix + kLightClientBootstrapTopic + kSchema1 + kEncodingProtocol};
const std::string kLightClientUpdatesByRangeV1{kProtocolPrefix + kLightClientUpdatesByRangeTopic + kSchema1 + kEncodingProtocol};

}  // namespace silkworm::cl::sentinel
