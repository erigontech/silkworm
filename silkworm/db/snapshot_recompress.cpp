/*
   Copyright 2024 The Silkworm Authors

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

#include <algorithm>
#include <stdexcept>

#include <silkworm/infra/common/directories.hpp>

#include "bodies/body_snapshot.hpp"
#include "headers/header_snapshot.hpp"
#include "snapshots/path.hpp"
#include "transactions/txn_snapshot.hpp"

namespace silkworm::snapshots {

template <class TSnapshotReader, class TSnapshotWriter>
void copy_reader_to_writer(const Snapshot& file_reader, SnapshotFileWriter& file_writer) {
    TSnapshotReader reader{file_reader};
    TSnapshotWriter writer{file_writer};
    std::copy(reader.begin(), reader.end(), writer.out());
}

void snapshot_file_recompress(const std::filesystem::path& path) {
    auto path_opt = SnapshotPath::parse(path);
    if (!path_opt) throw std::runtime_error{"bad snapshot path"};

    Snapshot file_reader{*path_opt};
    file_reader.reopen_segment();

    auto out_path = path;
    out_path.replace_extension("seg2");
    TemporaryDirectory tmp_dir;
    SnapshotFileWriter file_writer{*SnapshotPath::parse(out_path), tmp_dir.path()};

    switch (path_opt->type()) {
        case SnapshotType::headers:
            copy_reader_to_writer<HeaderSnapshotReader, HeaderSnapshotWriter>(file_reader, file_writer);
            break;
        case SnapshotType::bodies:
            copy_reader_to_writer<BodySnapshotReader, BodySnapshotWriter>(file_reader, file_writer);
            break;
        case SnapshotType::transactions:
            copy_reader_to_writer<TransactionSnapshotReader, TransactionSnapshotWriter>(file_reader, file_writer);
            break;
        default:
            throw std::runtime_error{"invalid snapshot type"};
    }

    SnapshotFileWriter::flush(std::move(file_writer));
}

}  // namespace silkworm::snapshots
