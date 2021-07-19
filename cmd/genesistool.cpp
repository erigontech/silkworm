/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <boost/algorithm/string.hpp>

namespace fs = std::filesystem;

void to_byte_array(fs::path& in, fs::path& out) {
    std::pair<std::regex, std::string> replacements[] = {
        {std::regex("\n+"), ""},  // New lines
        {std::regex("  "), " "},  // Double spaces
        {std::regex(": \""), ":\""}, {std::regex(": \\{"), ":{"},
        {std::regex(": \\["), ":["}, {std::regex(": ([0-9]{1,}),"), ":$1,"}};

    size_t input_size{fs::file_size(in)};
    if (!input_size) {
        return;
    }
    std::vector<uint8_t> bytes{};
    bytes.reserve(input_size);

    // Read and process input file
    std::ifstream in_stream(in.string());
    std::string line;
    while (std::getline(in_stream, line)) {
        // Remove leading trailing spaces
        boost::algorithm::trim(line);
        // Condense (remove the beautyfication)
        for (auto& [r, s] : replacements) {
            line = std::regex_replace(line, r, s);
        }
        // Append to byte vector
        std::transform(line.begin(), line.end(), std::back_inserter(bytes),
                       [](unsigned char c) { return static_cast<uint8_t>(c); });
    }
    in_stream.close();

    // Write bytes to output file
    std::string var_name{in.filename().replace_extension("").string()};
    std::ofstream out_stream{out.string()};
    out_stream << "/* Generated from " << in.string() << " using silkworm's genesistool*/" << std::endl;
    out_stream << "#include <stddef.h>" << std::endl;
    out_stream << "static const char " << var_name << "_data_internal[] = {" << std::endl;

    auto max{bytes.size()};
    auto count{1u};
    for (auto& b : bytes) {
        out_stream << "0x" << std::hex << static_cast<int>(b) << ((count == max) ? "" : ",")
                   << ((count % 16 == 0) ? "\n" : " ");
        ++count;
    }
    out_stream << "};" << std::endl;
    out_stream << "const char* " << var_name << "_data(void){return &" << var_name << "_data_internal[0];}"
               << std::endl;
    out_stream << "size_t sizeof_" << var_name << "_data(void){return sizeof(" << var_name << "_data_internal);}"
               << std::endl;
    out_stream.close();
}

int main(int argc, char* argv[]) {
    CLI::App app_main("Genesis Json to Cpp conversion tool");

    std::string input_dir{};
    std::string output_dir{};
    bool overwrite{false};

    app_main.add_option("-i,--input", input_dir, "Input directory for genesis json files", false)
        ->required()
        ->check(CLI::ExistingDirectory);
    app_main.add_option("-o,--output", output_dir, "Output directory for generated cpp byte arrays", false)
        ->required()
        ->check(CLI::ExistingDirectory);

    app_main.add_flag("-w,--overwrite", overwrite, "Whether to overwrite existing files");

    CLI11_PARSE(app_main, argc, argv);

    // Get genesis files in input directory
    static const std::regex genesis_pattern{R"(^genesis\_(.*)?\.json$)", std::regex_constants::icase};
    fs::path input_path{input_dir};
    if (input_path.has_filename()) {
        input_path += fs::path::preferred_separator;
    }
    std::vector<fs::directory_entry> input_entries{};
    for (auto directory_entry : fs::directory_iterator(input_path)) {
        std::string file_name{directory_entry.path().filename().string()};
        if (std::regex_match(file_name, genesis_pattern)) {
            input_entries.push_back(directory_entry);
        }
    }
    if (!input_entries.size()) {
        std::cerr << "\nNo files matching genesis pattern in input directory" << std::endl;
        return -1;
    }

    for (auto& directory_entry : input_entries) {
        fs::path input_file_path{directory_entry.path()};
        fs::path output_file_path{directory_entry.path()};
        output_file_path.replace_extension(".cpp");
        bool exists{fs::exists(output_file_path)};
        bool skip{exists && !overwrite};
        std::cout << input_file_path.string() << (skip ? " Skipped (exists)" : " -> " + output_file_path.string())
                  << std::endl;
        if (exists && !skip) {
            fs::remove(output_file_path);
        }
        if (!skip) {
            to_byte_array(input_file_path, output_file_path);
        }
    }

    return 0;
}
