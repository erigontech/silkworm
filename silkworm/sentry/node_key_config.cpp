// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_key_config.hpp"

#include <fstream>
#include <stdexcept>

#include <silkworm/core/common/util.hpp>

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
        throw runtime_error("NodeKeyConfig::load failed to parse a hex string in the node key file");

    return EccKeyPair{data.value()};
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
        }
        config = NodeKeyConfig(get<fs::path>(node_key_option.value()));
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
