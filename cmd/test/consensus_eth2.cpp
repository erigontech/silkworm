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

#include <atomic>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <gsl/util>
#include <magic_enum.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/common/terminal.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/concurrency/thread_pool.hpp>
#include <silkworm/lightclient/types/types.hpp>
#include <silkworm/lightclient/util/snappy_codec.hpp>

// See https://github.com/ethereum/consensus-specs/tests/formats/ssz_static/core.md

using namespace silkworm;

namespace fs = std::filesystem;

static const fs::path kGeneralTestConfigDir{"general"};
static const fs::path kMainnetTestConfigDir{"mainnet"};
static const fs::path kMinimalTestConfigDir{"minimal"};

static const char* kSszStatic{"ssz_static"};

std::atomic<size_t> total_passed{0};
std::atomic<size_t> total_failed{0};
std::atomic<size_t> total_skipped{0};

enum class TestStatus {
    kPassed,
    kFailed,
    kSkipped
};

using TestHandler = std::function<TestStatus(ByteView)>;

struct TestRunner {
    virtual ~TestRunner() = default;

    virtual void run(const fs::path& test_case_dir) const = 0;

  protected:
    static silkworm::Bytes read_file(const fs::path& binary_file) {
        std::ifstream ifs{binary_file, std::ios ::binary};
        if (!ifs) throw std::runtime_error{"cannot open file: " + binary_file.string()};
        auto _ = gsl::finally([&ifs]() { ifs.close(); });
        return {std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};
    }

    std::map<std::string, TestHandler> handlers_;
};

struct SszStaticTestRunner : public TestRunner {
    static inline const char* kRoots{"roots.yaml"};
    static inline const char* kSerialized{"serialized.ssz_snappy"};
    static inline const char* kValue{"value.yaml"};

    explicit SszStaticTestRunner() {
        handlers_.emplace("AttestationData", decode_test<cl::AttestationData>);
        handlers_.emplace("BeaconBlockHeader", decode_test<cl::BeaconBlockHeader>);
        handlers_.emplace("Checkpoint", decode_test<cl::Checkpoint>);
        handlers_.emplace("Eth1Data", decode_test<cl::Eth1Data>);
        handlers_.emplace("IndexedAttestation", decode_test<cl::IndexedAttestation>);
        handlers_.emplace("ProposerSlashing", decode_test<cl::ProposerSlashing>);
        handlers_.emplace("SignedBeaconBlockHeader", decode_test<cl::SignedBeaconBlockHeader>);
    }

    void run(const fs::path& test_case_dir) const override {
        const auto roots = read_file(test_case_dir / kRoots);
        SILK_DEBUG << "roots: " << silkworm::to_hex(roots);
        const auto serialized = read_file(test_case_dir / kSerialized);
        SILK_DEBUG << "serialized: " << silkworm::to_hex(serialized);
        const auto value = read_file(test_case_dir / kValue);
        SILK_DEBUG << "value: " << silkworm::to_hex(value);

        const auto test_case{test_case_dir.filename().string()};
        const auto test_suite{test_case_dir.parent_path().filename().string()};
        const auto test_handler{test_case_dir.parent_path().parent_path().filename().string()};
        SILK_DEBUG << "test: handler=" << test_handler << " suite=" << test_suite << " case=" << test_case;
        auto test_handler_it = handlers_.find(test_handler);
        if (test_handler_it != handlers_.cend()) {
            TestHandler test_handler_func = test_handler_it->second;
            SILK_DEBUG << "test: handler=" << test_handler << " suite=" << test_suite << " case=" << test_case;
            const TestStatus status = test_handler_func(serialized);
            switch (status) {
                case TestStatus::kPassed:
                    total_passed++;
                    break;
                case TestStatus::kFailed:
                    total_failed++;
                    break;
                case TestStatus::kSkipped:
                    total_skipped++;
                    break;
            }
        }
    }

  private:
    template <class T>
    static TestStatus decode_test(ByteView serialized) {
        SILK_DEBUG << "serialized: " << silkworm::to_hex(serialized);
        Bytes decompressed = snappy::decompress(serialized);
        T data;
        const DecodingResult result = ssz::decode<T>(decompressed, data);
        SILK_DEBUG << "result: " << magic_enum::enum_name(result);
        return result == DecodingResult::kOk ? TestStatus::kPassed : TestStatus::kFailed;
    }
};

void add_test_case(thread_pool& pool, const fs::path& test_case_dir, const TestRunner* runner) {
    pool.push_task([=]() { runner->run(test_case_dir); });
}

void add_test_suite(thread_pool& pool, const fs::path& test_suite_dir, const TestRunner* runner) {
    SILK_TRACE << "test_suite dir: " << test_suite_dir.string() << "\n";
    for (auto c = fs::directory_iterator(test_suite_dir); c != fs::directory_iterator{}; ++c) {
        const auto& test_case_path{c->path()};
        if (!fs::is_directory(test_case_path)) continue;
        SILK_TRACE << "test_case name: " << test_case_path.filename().string() << "\n";
        add_test_case(pool, test_case_path, runner);
    }
}

void add_test_handler(thread_pool& pool, const fs::path& test_handler_dir, const TestRunner* runner) {
    SILK_TRACE << "test_handler dir: " << test_handler_dir.string();
    for (auto s = fs::directory_iterator(test_handler_dir); s != fs::directory_iterator{}; ++s) {
        const auto& test_suite_path{s->path()};
        if (!fs::is_directory(test_suite_path)) continue;
        SILK_TRACE << "test_suite name: " << test_suite_path.filename().string();
        add_test_suite(pool, test_suite_path, runner);
    }
}

void add_test_runner(thread_pool& pool, const fs::path& test_runner_dir, const TestRunner* runner) {
    SILK_TRACE << "test_runner dir: " << test_runner_dir.string() << "\n";
    for (auto h = fs::directory_iterator(test_runner_dir); h != fs::directory_iterator{}; ++h) {
        const auto& test_handler_path{h->path()};
        if (!fs::is_directory(test_handler_path)) continue;
        add_test_handler(pool, test_handler_path, runner);
    }
}

int main(int argc, char* argv[]) {
    StopWatch sw;
    sw.start();

    CLI::App app{"Run Ethereum 2.0 Beacon consensus tests"};

    std::string tests_path{SILKWORM_CONSENSUS_ETH2_TEST_DIR};
    app.add_option("--tests", tests_path, "Path to Eth2.0 consensus tests")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    unsigned int num_threads{std::thread::hardware_concurrency()};
    app.add_option("--threads", num_threads, "Number of parallel threads")->capture_default_str();
    bool include_slow_tests{false};
    app.add_flag("--slow", include_slow_tests, "Run slow tests");

    CLI11_PARSE(app, argc, argv);
    init_terminal();

    size_t stack_size{40 * kMebi};
#ifdef NDEBUG
    stack_size = 16 * kMebi;
#endif
    thread_pool thread_pool{num_threads, stack_size};

    const fs::path root_dir{tests_path};
    static const std::vector<fs::path> kTestConfigs{
        kMinimalTestConfigDir,
    };

    std::map<std::string, std::unique_ptr<TestRunner>> test_runners;
    test_runners.emplace(kSszStatic, std::make_unique<SszStaticTestRunner>());

    for (const auto& test_config : kTestConfigs) {
        const auto config_dir{root_dir / test_config};
        SILK_TRACE << "config dir: " << config_dir.string();
        for (auto p = fs::directory_iterator(config_dir); p != fs::directory_iterator{}; ++p) {
            SILK_TRACE << "fork or phase dir: " << p->path().string();
            for (const auto& test_runner : test_runners) {
                const auto runner_dir{p->path() / test_runner.first};
                add_test_runner(thread_pool, runner_dir, test_runner.second.get());
            }
        }
    }

    thread_pool.wait_for_tasks();

    std::cout << kColorGreen << total_passed << " tests passed" << kColorReset << ", ";
    if (total_failed != 0) {
        std::cout << kColorMaroonHigh;
    }
    std::cout << total_failed << " failed";
    if (total_failed != 0) {
        std::cout << kColorReset;
    }
    std::cout << ", " << total_skipped << " skipped";

    const auto [_, duration] = sw.lap();
    std::cout << " in " << StopWatch::format(duration) << std::endl;

    return total_failed != 0;
}
