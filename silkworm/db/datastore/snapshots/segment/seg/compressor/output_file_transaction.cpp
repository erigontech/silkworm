// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "output_file_transaction.hpp"

#include <cerrno>
#include <stdexcept>

#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>

#include <silkworm/core/common/assert.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace silkworm::snapshots::seg {

using namespace boost;
using namespace std;

class OutputFileTransactionImpl {
  public:
    OutputFileTransactionImpl(const filesystem::path& path, size_t buffer_size)
        : path_(path),
          tmp_path_(make_tmp_path(path)),
          fd_sink_(tmp_path_.string(), ios::out | ios::binary | ios::trunc),
          stream_(fd_sink_, static_cast<streamsize>(buffer_size)) {
        stream_.exceptions(ios::failbit | ios::badbit);
    }

    ~OutputFileTransactionImpl() {
        if (!done_) {
            stream_.close();
            fd_sink_.close();
            filesystem::remove(tmp_path_);
        }
    }

    void commit() {
        fsync();
        stream_.close();
        fd_sink_.close();
        filesystem::rename(tmp_path_, path_);
        done_ = true;
    }

    ostream& stream() { return stream_; }

  private:
    static filesystem::path make_tmp_path(const filesystem::path& path) {
        return path.string() + ".tmp";
    }

#ifdef _WIN32
    static void fsync_native(HANDLE handle) {
        BOOL ok = FlushFileBuffers(handle);
        if (!ok) {
            throw std::runtime_error("fsync_native error: " + std::to_string(GetLastError()));
        }
    }
#else
    static void fsync_native(int fd) {
        int err = ::fsync(fd);
        if (err) {
            throw std::runtime_error("fsync_native error: " + std::to_string(errno));
        }
    }
#endif

    void fsync() {
        SILKWORM_ASSERT(stream_.is_open());
        stream_.flush();
        fsync_native(fd_sink_.handle());
    }

    filesystem::path path_;
    filesystem::path tmp_path_;
    iostreams::file_descriptor_sink fd_sink_;
    iostreams::stream<iostreams::file_descriptor_sink> stream_;
    bool done_{false};
};

OutputFileTransaction::OutputFileTransaction(
    const filesystem::path& path,
    size_t buffer_size)
    : p_impl_(make_unique<OutputFileTransactionImpl>(path, buffer_size)) {}
OutputFileTransaction::~OutputFileTransaction() { static_assert(true); }

void OutputFileTransaction::commit() {
    p_impl_->commit();
}

ostream& OutputFileTransaction::stream() {
    return p_impl_->stream();
}

}  // namespace silkworm::snapshots::seg
