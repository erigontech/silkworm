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

#include <iostream>
#include <string>

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/log.hpp>

using namespace silkworm;

int ethbackend_async(const std::string& target);
int ethbackend_coroutines(const std::string& target);
int ethbackend(const std::string& target);
int kv_seek_async_callback(const std::string& target, const std::string& table_name, ByteView key, uint32_t timeout);
int kv_seek_async_coroutines(const std::string& target, const std::string& table_name, ByteView key, uint32_t timeout);
int kv_seek_async(const std::string& target, const std::string& table_name, ByteView key, uint32_t timeout);
int kv_seek_both(const std::string& target, const std::string& table_name, ByteView key, ByteView subkey);
int kv_seek(const std::string& target, const std::string& table_name, ByteView key);

ABSL_FLAG(std::string, key, "", "key as hex string w/o leading 0x");
ABSL_FLAG(LogLevel, log_verbosity, LogLevel::Critical, "logging level as string");
ABSL_FLAG(std::string, seekkey, "", "seek key as hex string w/o leading 0x");
ABSL_FLAG(std::string, subkey, "", "subkey as hex string w/o leading 0x");
ABSL_FLAG(std::string, tool, "", "gRPC remote interface tool name as string");
ABSL_FLAG(std::string, target, kDefaultTarget, "Erigon location as string <address>:<port>");
ABSL_FLAG(std::string, table, "", "database table name as string");
ABSL_FLAG(uint32_t, timeout, kDefaultTimeout.count(), "gRPC call timeout as integer");

int ethbackend_async() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    return ethbackend_async(target);
}

int ethbackend_coroutines() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    return ethbackend_coroutines(target);
}

int ethbackend() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    return ethbackend(target);
}

int kv_seek_async_callback() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto timeout{absl::GetFlag(FLAGS_timeout)};

    return kv_seek_async_callback(target, table_name, key_bytes.value(), timeout);
}

int kv_seek_async_coroutines() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto timeout{absl::GetFlag(FLAGS_timeout)};

    return kv_seek_async_coroutines(target, table_name, key_bytes.value(), timeout);
}

int kv_seek_async() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto timeout{absl::GetFlag(FLAGS_timeout)};

    return kv_seek_async(target, table_name, key_bytes.value(), timeout);
}

int kv_seek_both() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto subkey{absl::GetFlag(FLAGS_subkey)};
    const auto subkey_bytes = silkworm::from_hex(subkey);
    if (subkey.empty() || !subkey_bytes.has_value()) {
        std::cerr << "Parameter subkey is invalid: [" << subkey << "]\n";
        std::cerr << "Use --subkey flag to specify the subkey in key-value dupsort table\n";
        return -1;
    }

    return kv_seek_both(target, table_name, key_bytes.value(), subkey_bytes.value());
}

int kv_seek() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || target.find(":") == std::string::npos) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    return kv_seek(target, table_name, key_bytes.value());
}

int main(int argc, char* argv[]) {
    absl::SetProgramUsageMessage(
        "Execute specified Silkrpc tool:\n"
        "\tethbackend\t\t\tquery the Erigon/Silkworm ETHBACKEND remote interface\n"
        "\tethbackend_async\t\tquery the Erigon/Silkworm ETHBACKEND remote interface\n"
        "\tethbackend_coroutines\t\tquery the Erigon/Silkworm ETHBACKEND remote interface\n"
        "\tkv_seek\t\t\t\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_async\t\t\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_async_callback\t\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_async_coroutines\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_both\t\t\tquery using SEEK_BOTH the Erigon/Silkworm Key-Value (KV) remote interface to database\n");
    const auto positional_args = absl::ParseCommandLine(argc, argv);
    if (positional_args.size() < 2) {
        std::cerr << "No Silkrpc tool specified as first positional argument\n\n";
        std::cerr << absl::ProgramUsageMessage();
        return -1;
    }

    SILKRPC_LOG_VERBOSITY(absl::GetFlag(FLAGS_log_verbosity));

    const std::string tool{positional_args[1]};
    if (tool == "ethbackend_async") {
        return ethbackend_async();
    }
    if (tool == "ethbackend_coroutines") {
        return ethbackend_coroutines();
    }
    if (tool == "ethbackend") {
        return ethbackend();
    }
    if (tool == "kv_seek_async_callback") {
        return kv_seek_async_callback();
    }
    if (tool == "kv_seek_async_coroutines") {
        return kv_seek_async_coroutines();
    }
    if (tool == "kv_seek_async") {
        return kv_seek_async();
    }
    if (tool == "kv_seek_both") {
        return kv_seek_both();
    }
    if (tool == "kv_seek") {
        return kv_seek();
    }

    std::cerr << "Unknown tool " << tool << " specified as first argument\n\n";
    std::cerr << absl::ProgramUsageMessage();
    return -1;
}
