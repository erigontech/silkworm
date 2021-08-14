/*
   Copyright 2021 The Silkworm Authors

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

#include "genesis.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <stdexcept>

extern const char* genesis_mainnet_data(void);
extern size_t sizeof_genesis_mainnet_data(void);

extern const char* genesis_goerli_data(void);
extern size_t sizeof_genesis_goerli_data(void);

extern const char* genesis_rinkeby_data(void);
extern size_t sizeof_genesis_rinkeby_data(void);

namespace silkworm {

std::string read_genesis_data(unsigned int chain_id) {

    std::string ret{};
    switch (chain_id) {
        case 1:
            assert(sizeof_genesis_mainnet_data() != 0);
            ret.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
            break;
        case 4:
            assert(sizeof_genesis_rinkeby_data() != 0);
            ret.assign(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());
            break;
        case 5:
            assert(sizeof_genesis_goerli_data() != 0);
            ret.assign(genesis_goerli_data(), sizeof_genesis_goerli_data());
            break;
        default:
            ret = "{"; // <- Won't be lately parsed as valid json value
    };

    return ret;
}

//nlohmann::json silkworm::read_genesis_json(unsigned int chain_id) {
//    std::string source;
//    nlohmann::json ret;
//
//    switch (chain_id) {
//        case 1:
//            assert(sizeof_genesis_mainnet_data() != 0);
//            source.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
//            break;
//        case 4:
//            assert(sizeof_genesis_rinkeby_data() != 0);
//            source.assign(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());
//            break;
//        case 5:
//            assert(sizeof_genesis_goerli_data() != 0);
//            source.assign(genesis_goerli_data(), sizeof_genesis_goerli_data());
//            break;
//        default:
//            ret["Error"] = nlohmann::json::array();
//            ret["Error"].push_back(std::string(__FUNCTION__) + " : Provided chain id is unknown");
//            return ret;
//    };
//
//    auto genesis_json = nlohmann::json::parse(source, nullptr, /* allow_exceptions = */ false);
//    if (genesis_json == nlohmann::json::value_t::discarded) {
//        throw std::runtime_error("Unable to parse json for chain " + std::to_string(chain_id).append(" function : ") +
//                                 std::string(__FUNCTION__));
//    }
//    return genesis_json;
//}
//
//nlohmann::json read_genesis_json(std::filesystem::path source) {
//    namespace fs = std::filesystem;
//    nlohmann::json ret;
//
//    // Check source is valid input
//    if (!source.has_filename() || !fs::exists(source) || !fs::is_regular_file(source) || !fs::file_size(source)) {
//        ret["Error"] = nlohmann::json::array();
//        ret["Error"].push_back(std::string(__FUNCTION__) + " : Provided json source does not exist or is empty file");
//        return ret;
//    }
//
//    try {
//        // Read input file
//        std::string source_data;
//        std::ifstream ifs(source.string());
//        source_data = std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
//        auto source_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
//        if (source_json == nlohmann::json::value_t::discarded) {
//            ret["Error"] = nlohmann::json::array();
//            ret["Error"].push_back(std::string(__FUNCTION__) + " : Badly formatted json file");
//        } else {
//            ret = source_json;
//        }
//
//    } catch (const std::exception& ex) {
//        ret["Error"] = nlohmann::json::array();
//        ret["Error"].push_back(std::string(__FUNCTION__) + " : " + ex.what());
//    }
//
//    return ret;
//}

}  // namespace silkworm
