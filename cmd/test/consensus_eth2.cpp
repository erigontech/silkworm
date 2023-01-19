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
#include <type_traits>
#include <vector>

#include <CLI/CLI.hpp>
#include <magic_enum.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/common/terminal.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/concurrency/thread_pool.hpp>
#include <silkworm/lightclient/snappy/snappy_codec.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/attestation.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/beacon_block_header.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/beacon_block.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/deposits.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/eth1data.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/execution_payload.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/slashing.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/sync_aggregate.hpp>
#include <silkworm/lightclient/ssz/beacon-chain/volutary_exit.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>

// See https://github.com/ethereum/consensus-specs/tests/formats/ssz_static/core.md

using namespace silkworm;

namespace fs = std::filesystem;

static const fs::path kGeneralTestConfigDir{"general"};
static const fs::path kMainnetTestConfigDir{"mainnet"};
static const fs::path kMinimalTestConfigDir{"minimal"};

// static const char* kSszGeneric{"ssz_generic"};
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
    static void set_stop_at_fail(bool stop_at_fail) { stop_at_fail_ = stop_at_fail; }
    static void set_trace_on_fail(bool trace_on_fail) { trace_on_fail_ = trace_on_fail; }
    static void set_skip_snappy_fail(bool skip_snappy_fail) { skip_snappy_fail_ = skip_snappy_fail; }

    virtual ~TestRunner() = default;

    virtual void run(const fs::path& test_case_dir) const = 0;

  protected:
    static silkworm::Bytes read_file(const fs::path& binary_file) {
        std::ifstream ifs{binary_file, std::ios ::binary};
        if (!ifs) throw std::runtime_error{"cannot open file: " + binary_file.string()};
        return {std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};
    }

    static bool stop_at_fail_;
    static bool trace_on_fail_;
    static bool skip_snappy_fail_;

    std::map<std::string, TestHandler> handlers_;
};

bool TestRunner::stop_at_fail_{false};
bool TestRunner::trace_on_fail_{false};
bool TestRunner::skip_snappy_fail_{true};

template <typename T>
concept SszObject = std::is_base_of<::ssz::Container, T>::value;

struct SszStaticTestRunner : public TestRunner {
    static inline const char* kRoots{"roots.yaml"};
    static inline const char* kSerialized{"serialized.ssz_snappy"};
    static inline const char* kValue{"value.yaml"};

    explicit SszStaticTestRunner() {
        handlers_.emplace("Attestation", round_trip<eth::Attestation>);
        handlers_.emplace("AttestationData", round_trip<eth::AttestationData>);
        handlers_.emplace("AttesterSlashing", round_trip<eth::AttesterSlashing>);
        handlers_.emplace("BeaconBlockHeader", round_trip<eth::BeaconBlockHeader>);
        handlers_.emplace("BeaconBlockBody", round_trip<eth::BeaconBlockBody>);  // TODO(canepat) test vectors: 5 pass, 20 fail
        handlers_.emplace("Checkpoint", round_trip<eth::Checkpoint>);
        handlers_.emplace("Deposit", round_trip<eth::Deposit>);
        handlers_.emplace("DepositData", round_trip<eth::DepositData>);
        handlers_.emplace("Eth1Data", round_trip<eth::Eth1Data>);
        handlers_.emplace("IndexedAttestation", round_trip<eth::IndexedAttestation>);
        handlers_.emplace("ProposerSlashing", round_trip<eth::ProposerSlashing>);
        handlers_.emplace("SignedBeaconBlockHeader", round_trip<eth::SignedBeaconBlockHeader>);
        handlers_.emplace("VoluntaryExit", round_trip<eth::VoluntaryExit>);
        handlers_.emplace("SignedVoluntaryExit", round_trip<eth::SignedVoluntaryExit>);
        handlers_.emplace("SyncAggregate", round_trip<eth::SyncAggregate>);  // TODO(canepat) commitee bits size 64 or 4? 64 => all consensus tests fail in minimal
        // handlers_.emplace("ExecutionPayload", round_trip<eth::ExecutionPayload>);  // TODO(canepat) all test vectors fail
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
                    if (trace_on_fail_) {
                        SILK_ERROR << "test failed: " << test_case_dir.string() << " input: "
                                   << to_hex(snappy::decompress(serialized));
                    }
                    if (stop_at_fail_) {
                        const auto test_name{test_handler + "_" + test_suite + "_" + test_case};
                        throw std::logic_error{"first test failed: " + test_name};
                    }
                    break;
                case TestStatus::kSkipped:
                    total_skipped++;
                    break;
            }
        }
    }

  private:
    template <SszObject T>
    static TestStatus round_trip(ByteView serialized_input) {
        if (!snappy::is_valid_compressed_data(serialized_input)) {
            return skip_snappy_fail_ ? TestStatus::kSkipped : TestStatus::kFailed;
        }
        SILK_DEBUG << "serialized_input: " << silkworm::to_hex(serialized_input);
        Bytes uncompressed_input = snappy::decompress(serialized_input);
        SILK_DEBUG << "uncompressed_input: " << silkworm::to_hex(uncompressed_input);
        auto data = std::make_unique<T>();
        std::vector<uint8_t> uncompressed_input_v{uncompressed_input.cbegin(), uncompressed_input.cend()};
        const auto decoding_ok = data->deserialize(uncompressed_input_v.cbegin(), uncompressed_input_v.cend());
        SILK_DEBUG << "decoding_result: " << decoding_ok;
        if (!decoding_ok) {
            return TestStatus::kFailed;
        }
        const std::vector<uint8_t> uncompressed_output_v = data->serialize();
        Bytes uncompressed_output{uncompressed_output_v.cbegin(), uncompressed_output_v.cend()};
        SILK_DEBUG << "uncompressed_output: " << silkworm::to_hex(uncompressed_output);
        if (uncompressed_output != uncompressed_input) {
            return TestStatus::kFailed;
        }
        Bytes serialized_output = snappy::compress(uncompressed_output);
        SILK_DEBUG << "serialized_output: " << silkworm::to_hex(serialized_output);
        if (serialized_output == serialized_input) {
            return TestStatus::kPassed;
        } else {
            return skip_snappy_fail_ ? TestStatus::kSkipped : TestStatus::kFailed;
        }
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

    CLI::App app{"Ethereum beacon-chain consensus tests"};

    std::string tests_path{SILKWORM_CONSENSUS_ETH2_TEST_DIR};
    app.add_option("--tests", tests_path, "Path to Eth2.0 consensus tests")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    unsigned int num_threads{std::thread::hardware_concurrency()};
    app.add_option("--threads", num_threads, "Number of parallel threads")->capture_default_str();
    bool stop_at_fail{false};
    app.add_flag("--stop_at_fail", stop_at_fail, "Stop at first test failure");
    bool trace_on_fail{false};
    app.add_flag("--trace_on_fail", trace_on_fail, "Trace an error in case of any test failure");
    bool skip_snappy_fail{false};
    app.add_flag("--skip_snappy_fail", skip_snappy_fail, "Skip failures due to Snappy round-trip mismatches");
    std::string test;
    app.add_option("--test", test, "Execute single test: <handler>#<suite>#<case>")
        ->capture_default_str();

    CLI11_PARSE(app, argc, argv)
    init_terminal();

    size_t stack_size{40 * kMebi};
#ifdef NDEBUG
    stack_size = 16 * kMebi;
#endif
    thread_pool workers{num_threads, stack_size};

    const fs::path root_dir{tests_path};
    static const std::vector<fs::path> kTestConfigs{
        // kGeneralTestConfigDir,
        kMainnetTestConfigDir,
        // kMinimalTestConfigDir,
    };

    TestRunner::set_stop_at_fail(stop_at_fail);
    TestRunner::set_trace_on_fail(trace_on_fail);
    TestRunner::set_skip_snappy_fail(skip_snappy_fail);

    std::map<std::string, std::unique_ptr<TestRunner>> test_runners;
    // test_runners.emplace(kSszGeneric, std::make_unique<SszGenericTestRunner>());
    test_runners.emplace(kSszStatic, std::make_unique<SszStaticTestRunner>());

    for (const auto& test_config : kTestConfigs) {
        const auto config_dir{root_dir / test_config};
        SILK_TRACE << "config dir: " << config_dir.string();
        for (auto p = fs::directory_iterator(config_dir); p != fs::directory_iterator{}; ++p) {
            SILK_TRACE << "fork or phase dir: " << p->path().string();
            for (const auto& test_runner : test_runners) {
                const auto runner_dir{p->path() / test_runner.first};
                if (fs::exists(runner_dir)) {
                    add_test_runner(workers, runner_dir, test_runner.second.get());
                }
            }
        }
    }

    workers.wait_for_tasks();

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
