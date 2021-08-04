/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_DB_STAGEDSYNC_TRANSACTION_MANAGER_HPP_
#define SILKWORM_DB_STAGEDSYNC_TRANSACTION_MANAGER_HPP_

#include <mdbx.h++>

namespace silkworm::stagedsync {

// This class manages mdbx transactions for staged sync.
// It either creates new mdbx transactions as need be or uses an externally provided transaction.
// The external transaction mode is handy for running several stages on a handful of blocks atomically.
class TransactionManager {
  public:
    // This variant creates new mdbx transactions as need be.
    explicit TransactionManager(mdbx::env& env) : env_{&env} { managed_txn_ = env_->start_write(); }

    // This variant is just a wrapper over an external transaction.
    // Useful in staged sync for running several stages on a handful of blocks atomically.
    // The code that invokes the stages is responsible for committing the external txn later on.
    explicit TransactionManager(mdbx::txn& external_txn) : external_txn_{&external_txn} {}

    // Not copyable nor movable
    TransactionManager(const TransactionManager&) = delete;
    TransactionManager& operator=(const TransactionManager&) = delete;

    mdbx::txn& operator*() { return external_txn_ ? *external_txn_ : managed_txn_; }

    mdbx::txn* operator->() { return external_txn_ ? external_txn_ : &managed_txn_; }

    void commit() {
        if (external_txn_ == nullptr) {
            managed_txn_.commit();
            managed_txn_ = env_->start_write();  // renew transaction
        } else {
            // external_txn is useful for running several stages on a handful of blocks atomically.
            // The code that invokes the stages is responsible for committing external_txn_ later on.
        }
    }

  private:
    mdbx::txn* external_txn_{nullptr};
    mdbx::env* env_{nullptr};
    mdbx::txn_managed managed_txn_;
};

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_DB_STAGEDSYNC_TRANSACTION_MANAGER_HPP_
