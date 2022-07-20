
#pragma once

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

// todo: replace this class with IStage as soon as it will support the shared status
class Stage {
  public:
    enum Result { Unspecified, Done, DoneAndUpdated, UnwindNeeded, SkipTx, Error };

    struct Status {
        bool first_sync{false};
        std::optional<BlockNum> current_point;
        std::optional<BlockNum> unwind_point;
        std::optional<Hash> bad_block;
    };

    Stage(Status& s): shared_status_(s) {}
    Stage(const Stage& s): shared_status_(s.shared_status_) {}

    virtual Result forward(db::RWTxn&) = 0;
    virtual Result unwind(db::RWTxn&, BlockNum new_height) = 0;

  protected:
    Status& shared_status_;
};

}
