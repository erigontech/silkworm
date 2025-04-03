// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <boost/algorithm/string.hpp>

#include <silkworm/core/common/util.hpp>

namespace fs = std::filesystem;

void to_byte_array(fs::path& in, fs::path& out, const std::string& ns) {
    std::pair<std::regex, std::string> replacements[] = {
        {std::regex("\n+"), ""},  // New lines
        {std::regex("  "), " "},  // Double spaces
        {std::regex(": \""), ":\""},
        {std::regex(": \\{"), ":{"},
        {std::regex(": \\["), ":["},
        {std::regex(": ([0-9]{1,}),"), ":$1,"}};

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
        // Condense (remove the beautification)
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
    std::string const_name{"k" + silkworm::snake_to_camel(var_name)};
    std::ofstream out_stream{out.string()};
    out_stream << "/* Generated from " << in.filename().string() << " using silkworm embed_json tool */\n";
    out_stream << "#include \"" + var_name + ".hpp\"\n";
    out_stream << "constexpr char " << const_name << "DataInternal[] = {\n";

    auto max{bytes.size()};
    auto count{1u};
    for (auto& b : bytes) {
        out_stream << "0x" << std::hex << static_cast<int>(b) << ((count == max) ? "" : ",")
                   << ((count % 16 == 0) ? "\n" : " ");
        ++count;
    }
    out_stream << "};\n";
    out_stream << "namespace " + ns + " {\n";
    out_stream << "constinit const std::string_view " << const_name << "Json{&" << const_name
               << "DataInternal[0], sizeof(" << const_name << "DataInternal)};\n";
    out_stream << "}\n";
    out_stream.close();
}

int main(int argc, char* argv[]) {
    CLI::App app_main("JSON to C++ conversion tool");

    std::string input_dir{};
    std::string output_dir{};
    std::string pattern_prefix{"genesis_"};
    std::string ns{"silkworm"};
    bool overwrite{false};

    app_main.add_option("-i,--input", input_dir, "Input directory for JSON files")
        ->required()
        ->check(CLI::ExistingDirectory);
    app_main.add_option("-o,--output", output_dir, "Output directory for generated C++ source files")
        ->required()
        ->check(CLI::ExistingDirectory);
    app_main.add_option("-p,--pattern_prefix", pattern_prefix, "Regex pattern prefix to use for discovering the files");
    app_main.add_option("-n,--namespace", ns, "C++ namespace to use in generated code");

    app_main.add_flag("-w,--overwrite", overwrite, "Whether to overwrite existing files");

    CLI11_PARSE(app_main, argc, argv)

    // Get genesis files in input directory
    const std::string json_file_pattern{"(^" + pattern_prefix + "(.*)?\\.json$)"};
    const std::regex pattern{json_file_pattern, std::regex_constants::icase};
    fs::path input_path{input_dir};
    if (input_path.has_filename()) {
        input_path += fs::path::preferred_separator;
    }
    std::vector<fs::directory_entry> input_entries{};
    for (const auto& directory_entry : fs::directory_iterator(input_path)) {
        std::string file_name{directory_entry.path().filename().string()};
        if (std::regex_match(file_name, pattern)) {
            input_entries.push_back(directory_entry);
        }
    }
    if (input_entries.empty()) {
        std::cerr << "\nNo files matching pattern " + json_file_pattern + " in input directory\n";
        return -1;
    }

    for (auto& directory_entry : input_entries) {
        fs::path input_file_path{directory_entry.path()};
        fs::path output_file_path{directory_entry.path()};
        output_file_path.replace_extension(".cpp");
        bool exists{fs::exists(output_file_path)};
        bool skip{exists && !overwrite};
        std::cout << input_file_path.string() << (skip ? " skipped (already exists)" : " -> " + output_file_path.string()) << "\n";
        if (exists && !skip) {
            fs::remove(output_file_path);
        }
        if (!skip) {
            to_byte_array(input_file_path, output_file_path, ns);
        }
    }

    return 0;
}
