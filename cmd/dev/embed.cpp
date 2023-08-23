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

#include <cassert>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

#include <CLI/CLI.hpp>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    // Define the command line options
    CLI::App app{"Embed files as binary data"};

    std::string input_folder, output_folder, extension, suffix;
    app.add_option("-i,--input", input_folder, "input folder where to look for files")->required();
    app.add_option("-o,--output", output_folder, "output folder where to place generated .cpp files")->required();
    app.add_option("-e,--extension", extension, "extension of input files to look for")->required();
    app.add_option("-s,--suffix", suffix, "suffix for data structures in generated .cpp files")->required();

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
        // Skip any file in 'history' sub-folder
        if (entry_path.parent_path().string().ends_with("history")) {
            continue;
        }
        // Match only required extension
        if (entry_path.extension() == extension) {
            // Open the input .toml file
            std::ifstream input{entry_path.string(), std::ios::binary};
            if (!input.good()) continue;
            size_t input_size{fs::file_size(entry_path)};
            if (!input_size) continue;

            // Read the entire file in memory (this *must* be OK because we're embedding the file)
            std::vector<char> bytes(input_size);
            input.read(bytes.data(), static_cast<std::streamsize>(input_size));
            assert(static_cast<size_t>(input.gcount()) == input_size);

            std::cout << "Processing TOML file: " << entry_path.string() << "\n";

            // Open the output .cpp file
            fs::path entry_filename = entry.path().stem();
            entry_filename.replace_filename(std::regex_replace(entry_filename.string(), hyphen_re, "_"));
            fs::path output_path = fs::path{output_folder} / entry_filename.replace_extension(".cpp");
            std::ofstream output{output_path};

            // Write bytes from the input file to the output file as built-in array of characters
            std::string output_file_name = entry_filename.stem().string();

            output << "/* Generated from " << entry.path().filename().string() << " using Silkworm embed */\n\n";
            output << "#include <cstddef>\n\n";
            output << "static const char " << output_file_name << "_data[] = {\n";
            auto count{1u};
            for (auto& b : bytes) {
                output << "0x" << std::setfill('0') << std::hex << std::setw(2) << static_cast<int>(b)
                       << ((count == bytes.size()) ? "" : ",") << ((count % 16 == 0) ? "\n" : " ");
                ++count;
            }
            output << "};\n\n";
            output << "const char* " << output_file_name << "_" << suffix << "_data() { return &" << output_file_name << "_data[0]; }\n";
            output << "size_t " << output_file_name << "_" << suffix << "_size() { return sizeof(" << output_file_name << "_data); }\n";
        }
    }

    return 0;
}
