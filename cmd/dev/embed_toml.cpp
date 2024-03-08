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

namespace fs = std::filesystem;

std::string snake_to_camel(std::string_view snake) {
    std::string camel;
    camel += static_cast<char>(std::toupper(static_cast<unsigned char>(snake[0])));
    for (std::size_t i = 1; i < snake.length(); ++i) {
        if (snake[i] == '_' && (i + 1) < snake.length()) {
            camel += static_cast<char>(std::toupper(static_cast<unsigned char>(snake[++i])));
        } else {
            camel += snake[i];
        }
    }
    return camel;
}

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
            std::string snapshot_name = snake_to_camel(entry_filename.stem().string());

            output << "/* Generated from " << entry.path().filename().string() << " using Silkworm embed_toml */\n\n";
            output << "#pragma once\n\n";
            output << "#include <array>\n";
            output << "#include <string_view>\n\n";
            output << "#include <silkworm/db/snapshots/entry.hpp>\n\n";
            output << "namespace silkworm::snapshots {\n\n";
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
            output << "}\n";
        }
    }

    return 0;
}
