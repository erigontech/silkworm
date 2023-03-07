/*
   Copyright 2020 The Silkrpc Authors

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

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>

namespace silkrpc {

typedef std::vector<evmc::address> FilterAddresses;
typedef std::vector<evmc::bytes32> FilterSubTopics;
typedef std::vector<FilterSubTopics> FilterTopics;

struct Filter {
    std::optional<std::string> from_block;
    std::optional<std::string> to_block;
    std::optional<FilterAddresses> addresses;
    std::optional<FilterTopics> topics;
    std::optional<std::string> block_hash;
};

std::ostream& operator<<(std::ostream& out, const Filter& filter);

} // namespace silkrpc

std::ostream& operator<<(std::ostream& out, const std::optional<silkrpc::FilterAddresses>& addresses);

std::ostream& operator<<(std::ostream& out, const std::optional<silkrpc::FilterTopics>& topics);

