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

#include "node_key_config.hpp"

#include <fstream>

#include <silkworm/common/util.hpp>

namespace silkworm::sentry {

using namespace std;
namespace fs = filesystem;

NodeKeyConfig::NodeKeyConfig(fs::path path)
    : path_(std::move(path)) {
}

NodeKeyConfig::NodeKeyConfig(const DataDirectory& data_dir)
    : NodeKeyConfig(data_dir.path() / "nodekey") {
}

NodeKey NodeKeyConfig::load() const {
    string contents;
    ifstream file{path_};
    file.exceptions(ios::failbit | ios::badbit);
    file >> contents;

    auto data = from_hex(contents);
    if (!data)
        throw runtime_error("Failed to parse a hex string in the node key file");

    return common::EccKeyPair{data.value()};
}

void NodeKeyConfig::save(const NodeKey& key) const {
    ofstream file{path_};
    file.exceptions(ios::failbit | ios::badbit);
    file << key.private_key_hex();
}

bool NodeKeyConfig::exists() const {
    return fs::exists(path_);
}

NodeKey node_key_get_or_generate(
    const optional<variant<fs::path, Bytes>>& node_key_option,
    const DataDirectory& data_dir) {
    NodeKeyConfig config{data_dir};

    if (node_key_option) {
        const Bytes* data = get_if<Bytes>(&node_key_option.value());
        if (data) {
            return NodeKey(*data);
        } else {
            config = NodeKeyConfig(get<fs::path>(node_key_option.value()));
        }
    }

    if (config.exists()) {
        return config.load();
    }

    // generate and save a new key
    NodeKey key;
    config.save(key);
    return key;
}

}  // namespace silkworm::sentry
