// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log_cbor.hpp"

#include <cstring>
#include <utility>

#include <cbor/decoder.h>
#include <cbor/encoder.h>
#include <cbor/input.h>
#include <cbor/output_dynamic.h>

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm {

Bytes cbor_encode(const std::vector<Log>& v) {
    cbor::output_dynamic output{};
    cbor::encoder encoder{output};

    encoder.write_array(static_cast<int>(v.size()));

    for (const Log& l : v) {
        encoder.write_array(3);
        encoder.write_bytes(l.address.bytes, kAddressLength);
        encoder.write_array(static_cast<int>(l.topics.size()));
        for (const evmc::bytes32& t : l.topics) {
            encoder.write_bytes(t.bytes, kHashLength);
        }
        encoder.write_bytes(l.data.data(), static_cast<unsigned>(l.data.size()));
    }

    return Bytes{output.data(), output.size()};
}

//! LogCborListener is a *stateful* CBOR consumer suitable for parsing a CBOR-encoded sequence of Logs
class LogCborListener : public cbor::listener {
  private:
    enum class ProcessingState {
        kWaitLogs,
        kWaitLog,
        kWaitAddress,
        kWaitTopics,
        kWaitTopic,
        kWaitData
    };

  public:
    explicit LogCborListener(LogCborConsumer& consumer) : consumer_{consumer} {}

    void on_integer(int) override {
        ensure(false, "Log CBOR: unexpected format (on_integer called)");
    }

    void on_map(int) override {
        ensure(false, "Log CBOR: unexpected format (on_map called)");
    }

    void on_string(std::string&) override {
        ensure(false, "Log CBOR: unexpected format (on_string called)");
    }

    void on_tag(unsigned int) override {
        ensure(false, "Log CBOR: unexpected format (on_tag called)");
    }

    void on_undefined() override {
        ensure(false, "Log CBOR: unexpected format (on_undefined called)");
    }

    void on_extra_integer(unsigned long long, int) override {  // NOLINT(google-runtime-int)
        ensure(false, "Log CBOR: unexpected format (on_extra_integer called)");
    }

    void on_bool(bool) override {
        ensure(false, "Log CBOR: unexpected format (on_bool called)");
    }

    void on_extra_tag(unsigned long long) override {  // NOLINT(google-runtime-int)
        ensure(false, "Log CBOR: unexpected format (on_extra_tag called)");
    }

    void on_float32(float) override {
        ensure(false, "Log CBOR: unexpected format (on_float32 called)");
    }

    void on_double(double) override {
        ensure(false, "Log CBOR: unexpected format (on_double called)");
    }

    void on_extra_special(unsigned long long) override {  // NOLINT(google-runtime-int)
        ensure(false, "Log CBOR: unexpected format (on_extra_special called)");
    }

    void on_error(const char* what) override {
        throw std::runtime_error("Log CBOR: unexpected decoding error: " + std::string{what});
    }

    void on_special(unsigned int) override {
        ensure(false, "Log CBOR: unexpected format (on_special called)");
    }

    void on_null() override {
        ensure(false, "Log CBOR: unexpected format (on_null called)");
    }

    void on_bytes(unsigned char* data, int size) override {
        ensure(size >= 0, "Log CBOR: unexpected format (on_bytes called with negative size)");
        const auto data_size{static_cast<size_t>(size)};

        if (state_ == ProcessingState::kWaitAddress) {
            ensure(data_size == kAddressLength, [&]() { return "Log CBOR: unexpected address size " + std::to_string(data_size); });
            consumer_.on_address(std::span<const uint8_t, kAddressLength>{data, data_size});
            state_ = ProcessingState::kWaitTopics;
        } else if (state_ == ProcessingState::kWaitTopic) {
            ensure(data_size == kHashLength, [&]() { return "Log CBOR: unexpected topic size " + std::to_string(data_size); });
            consumer_.on_topic(HashAsSpan{data, data_size});
            if (++current_topic_ == current_num_topics_) {
                state_ = ProcessingState::kWaitData;
            }
        } else if (state_ == ProcessingState::kWaitData) {
            consumer_.on_data(std::span<const uint8_t>{data, data_size});
            state_ = ++current_log_ == current_num_logs_ ? ProcessingState::kWaitLogs : ProcessingState::kWaitLog;
        } else {
            ensure(false, "Log CBOR: unexpected format (on_bytes bad state)");
        }
    }

    void on_array(int size) override {
        ensure(size >= 0, "Log CBOR: unexpected format (on_array called with negative size)");
        const auto array_size{static_cast<size_t>(size)};

        if (state_ == ProcessingState::kWaitLogs) {
            consumer_.on_num_logs(array_size);
            state_ = ProcessingState::kWaitLog;
            current_num_logs_ = array_size;
            current_log_ = 0;
        } else if (state_ == ProcessingState::kWaitLog) {
            ensure(array_size == 3, [&]() { return "Log CBOR: unexpected number of Log fields " + std::to_string(array_size); });
            state_ = ProcessingState::kWaitAddress;
        } else if (state_ == ProcessingState::kWaitTopics) {
            consumer_.on_num_topics(array_size);
            state_ = array_size == 0 ? ProcessingState::kWaitData : ProcessingState::kWaitTopic;
            current_num_topics_ = array_size;
            current_topic_ = 0;
        } else {
            ensure(false, "Log CBOR: unexpected format (on_array bad state)");
        }
    }

  protected:
    LogCborConsumer& consumer_;
    ProcessingState state_{ProcessingState::kWaitLogs};
    size_t current_num_logs_{0};
    size_t current_log_{0};
    size_t current_num_topics_{0};
    size_t current_topic_{0};
};

void cbor_decode(ByteView data, LogCborConsumer& consumer) {
    cbor::input input(data.data(), static_cast<int>(data.size()));
    LogCborListener listener{consumer};
    cbor::decoder decoder(input, listener);
    decoder.run();
}

//! LogBuilder is a CBOR consumer which builds a sequence of Logs from their CBOR representation
class LogBuilder : public LogCborConsumer {
  public:
    explicit LogBuilder(std::vector<Log>& logs) : logs_{logs}, current_log_{} {}

    bool success() const {
        return std::cmp_equal(logs_.size(), current_num_logs_);
    }

    void on_num_logs(size_t num_logs) override {
        current_num_logs_ += num_logs;
        logs_.reserve(num_logs);
    }

    void on_address(std::span<const uint8_t, kAddressLength> address_bytes) override {
        std::memcpy(current_log_.address.bytes, address_bytes.data(), address_bytes.size());
    }

    void on_num_topics(size_t num_topics) override {
        current_log_.topics.reserve(num_topics);
    }

    void on_topic(HashAsSpan topic_bytes) override {
        evmc::bytes32 topic;
        std::memcpy(topic.bytes, topic_bytes.data(), topic_bytes.size());
        current_log_.topics.emplace_back(topic);
    }

    void on_data(std::span<const uint8_t> data_bytes) override {
        current_log_.data.resize(data_bytes.size());
        std::memcpy(current_log_.data.data(), data_bytes.data(), data_bytes.size());
        logs_.emplace_back(std::move(current_log_));
        current_log_ = {};
    }

  private:
    std::vector<Log>& logs_;
    Log current_log_;
    size_t current_num_logs_{0};
};

bool cbor_decode(ByteView data, std::vector<Log>& logs) {
    LogBuilder builder{logs};
    cbor_decode(data, builder);
    return builder.success();
}

}  // namespace silkworm
