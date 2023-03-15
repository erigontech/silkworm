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

#include <string>

#include <CLI/CLI.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/lightclient/snappy/snappy_codec.hpp>
#include <silkworm/lightclient/snappy/stream_codec.hpp>
#include <silkworm/node/rpc/common/util.hpp>

#include "common.hpp"

using namespace silkworm;
using namespace silkworm::cmd;

//! The Snappy compression format
enum class SnappyCompressionFormat {
    block,
    framing
};

//! The Snappy compression function
enum class SnappyCompressionFunction {
    encode,
    decode,
    roundtrip
};

//! The settings for the Snappy toolbox
struct SnappyToolboxSettings {
    log::Settings log_settings;
    SnappyCompressionFormat format{SnappyCompressionFormat::framing};
    SnappyCompressionFunction function{SnappyCompressionFunction::decode};
    std::string input;
};

SnappyToolboxSettings parse_cli_settings(int argc, char* argv[]) {
    CLI::App cli{"Silkworm Snappy Codec"};

    try {
        SnappyToolboxSettings settings;
        add_logging_options(cli, settings.log_settings);

        std::map<std::string, SnappyCompressionFormat> snappy_compression_mapping{
            {"block", SnappyCompressionFormat::block},
            {"framing", SnappyCompressionFormat::framing},
        };
        cli.add_flag("-b{block},-f{framing}", settings.format, "Flag indicating if block or framing format will be used")
            ->transform(CLI::Transformer(snappy_compression_mapping, CLI::ignore_case))
            ->default_val(SnappyCompressionFormat::framing);
        auto* group = cli.add_option_group("encoding/decoding");
        auto* encoding = group->add_option("--encode,-e", settings.input, "Input hex string for Snappy encoding");
        auto* decoding = group->add_option("--decode,-d", settings.input, "Input hex string for Snappy decoding");
        group->add_option("--roundtrip,-r", settings.input, "Input hex string for Snappy round-trip");
        group->require_option(1);

        const auto version = get_node_name_from_build_info(silkworm_get_buildinfo());
        cli.set_version_flag("--version,-v", version);

        cli.parse(argc, argv);

        if (*encoding) {
            settings.function = SnappyCompressionFunction::encode;
        } else if (*decoding) {
            settings.function = SnappyCompressionFunction::decode;
        } else {
            settings.function = SnappyCompressionFunction::roundtrip;
        }

        return settings;
    } catch (const CLI::ParseError& pe) {
        cli.exit(pe);
        throw;
    }
}

int main(int argc, char* argv[]) {
    try {
        SnappyToolboxSettings settings = parse_cli_settings(argc, argv);
        log::init(settings.log_settings);

        const auto input = from_hex(settings.input);
        if (!input) {
            throw std::runtime_error{"invalid hex input"};
        }

        Bytes output;
        if (settings.format == SnappyCompressionFormat::block) {
            if (settings.function == SnappyCompressionFunction::encode) {
                output = snappy::compress(*input);
            } else if (settings.function == SnappyCompressionFunction::decode) {
                output = snappy::decompress(*input);
            } else {
                const auto compressed = snappy::compress(*input);
                output = snappy::decompress(compressed);
            }
        } else {  // settings.format == SnappyCompressionFormat::framing
            if (settings.function == SnappyCompressionFunction::encode) {
                output = snappy::framing_compress(*input);
            } else if (settings.function == SnappyCompressionFunction::decode) {
                output = snappy::framing_uncompress(*input);
            } else {
                const auto compressed = snappy::framing_compress(*input);
                output = snappy::framing_uncompress(compressed);
            }
        }
        std::cout << to_hex(ByteView{reinterpret_cast<uint8_t*>(output.data()), output.size()}) << "\n"
                  << std::flush;
        return 0;
    } catch (const CLI::ParseError& pe) {
        return -1;
    } catch (const std::exception& e) {
        log::Critical() << "SnappyCodec exiting due to exception: " << e.what();
        return -2;
    } catch (...) {
        log::Critical() << "SnappyCodec exiting due to unexpected exception";
        return -3;
    }
}
