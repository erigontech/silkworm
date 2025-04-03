// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cctype>
#include <filesystem>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <string_view>

#include <CLI/CLI.hpp>
#include <absl/strings/match.h>
#include <toml.hpp>

#include <silkworm/core/common/util.hpp>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    // Define the command line options
    CLI::App app{"Embed files as binary data"};

    std::string input_folder, output_folder;
    bool include_beacon{false};
    app.add_option("-i,--input", input_folder, "input folder where to look for files")->required();
    app.add_option("-o,--output", output_folder, "output folder where to place generated .hpp files")->required();
    app.add_flag("-b,--beacon-blocks", include_beacon, "includes also beacon-chain segments");

    // Parse the command line arguments
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    const std::regex hyphen_re{"-"};

    // Iterating through all the files in the input folder
    for (const auto& entry : fs::recursive_directory_iterator(input_folder)) {
        const fs::path& entry_path = entry.path();
        // Skip any file in 'webseed' sub-folder
        if (entry_path.parent_path().string().ends_with("webseed")) {
            continue;
        }
        // Match only required extension
        if (entry_path.extension() == ".toml") {
            std::cout << "Processing TOML file: " << entry_path.string() << "\n";
            const auto table = toml::parse_file(entry_path.string());

            // Open the output .hpp file
            fs::path entry_filename = entry.path().stem();
            entry_filename.replace_filename(std::regex_replace(entry_filename.string(), hyphen_re, "_"));
            fs::path output_path = fs::path{output_folder} / entry_filename.replace_extension(".hpp");
            std::ofstream output{output_path};

            // Write the snapshots as a constexpr std::array
            std::string snapshot_name = silkworm::snake_to_camel(entry_filename.stem().string());

            output << "/* Generated from " << entry.path().filename().string() << " using Silkworm embed_toml */\n\n";
            output << "#pragma once\n\n";
            output << "#include <array>\n";
            output << "#include <string_view>\n\n";
            output << "#include \"../entry.hpp\"\n\n";
            output << "namespace silkworm::snapshots {\n\n";
            output << "using namespace std::literals;\n\n";
            output << "inline constexpr std::array k" << snapshot_name << "Snapshots{\n";
            for (auto&& [key, value] : table) {
                std::string key_str{key.begin(), key.end()};
                if (!include_beacon && absl::StrContains(key_str, "beaconblocks")) {
                    continue;
                }
                std::string val_str{value.as_string()->get()};
                output << "    Entry{\"" << key_str << "\"sv, \"" << val_str << "\"sv},\n";
            }
            output << "};\n\n";
            output << "}  // namespace silkworm::snapshots\n";
        }
    }

    return 0;
}
