/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_DB_CHAINDB_H_
#define SILKWORM_DB_CHAINDB_H_

/**
 * Wrappers for the LMDB database library.
 * See http://www.lmdb.tech/doc/index.html
 */

#include <lmdb/lmdb.h>

#include <boost/signals2/signal.hpp>
#include <exception>
#include <map>
#include <mutex>
#include <optional>
#include <silkworm/common/base.hpp>
#include <silkworm/db/util.hpp>
#include <string>
#include <thread>
#include <vector>

static_assert(sizeof(size_t) == 8, "32 bit environment limits LMDB size");

namespace silkworm::lmdb {

/**
 * Options to pass to env when opening file
 */
struct options {
    uint64_t map_size = 1ull << 40;  // 1 TiB by default
    bool no_tls = true;              // MDB_NOTLS
    bool no_rdahead = true;          // MDB_NORDAHEAD
    bool no_sync = true;             // MDB_NOSYNC
    bool no_meta_sync = false;       // MDB_NOMETASYNC
    bool write_map = false;          // MDB_WRITEMAP
    bool no_sub_dir = false;         // MDB_NOSUBDIR
    bool read_only = true;           // MDB_RDONLY
    unsigned max_tables = 128;       // Max open tables/dbi
    mdb_mode_t mode = 0644;          // Filesystem mode (works only for Linux)
};

static const MDB_dbi FREE_DBI = 0;  // Reserved for tracking free pages
static const MDB_dbi MAIN_DBI = 1;  // Reserved for tracking named tables

struct TableConfig {
    const char* name{nullptr};
    const unsigned int flags{0};
    //bool dupsort{false};  // MDB_DUPSORT
};

/**
 * Exception thrown by lmdb
 */
class exception : public std::exception {
   public:
    explicit exception(int err, const char* message) : err_{err}, message_{message} {};
    explicit exception(int err, const std::string& message) : err_{err}, message_{message} {};
    virtual ~exception() noexcept {};
    const char* what() const noexcept override { return message_.c_str(); }
    int err() const noexcept { return err_; }

   protected:
    int err_;
    std::string message_;
};

/**
 * Handles return codes from API calls and throws if not MDB_SUCCESS
 */
inline void err_handler(int err) {
    if (err != MDB_SUCCESS) {
        throw exception(err, mdb_strerror(err));
    }
}

class Transaction;
class Table;

/**
 * MDB_env wrapper
 */
class Environment {
   private:
    MDB_env* handle_{nullptr};  // Handle to MDB_env
    bool opened_{false};        // Whether or not the handle has an underlying opened db

    friend class Transaction;

    std::mutex count_mtx_;                      // Lock to prevent concurrent access to transactions counters maps
    std::map<std::thread::id, int> ro_txns_{};  // A per thread maintained count of opened ro transactions
    std::map<std::thread::id, int> rw_txns_{};  // A per thread maintained count of opened rw transactions

    /*
     * A transaction and its cursors must only be used by a single thread,
     * and a thread may only have one transaction at a time.
     * Only exception is when parent environment is opened with MDB_NOTLS flag
     * which causes the allowance of unlimited ro transactions.
     * So when a thread begins a new transaction (see begin_transaction)
     * env is checked for corresponding slot and eventually allows or
     * prohibits the transaction opening
     */

    int get_ro_txns(void);          // Returns number of opened ro transactions for calling thread
    int get_rw_txns(void);          // Returns number of opened rw transactions for calling thread
    void touch_ro_txns(int count);  // Ro transaction count incrementer/decrementer
    void touch_rw_txns(int count);  // Ro transaction count incrementer/decrementer

    bool assert_handle(bool should_throw = true);  // Ensures handle_ is validly created
    bool assert_opened(bool should_throw = true);  // Ensures database is validly opened

   public:
    explicit Environment(const unsigned flags = 0);
    ~Environment() noexcept;

    MDB_env** handle(void) { return &handle_; }
    bool is_opened(void) { return opened_; }
    bool is_ro(void);

    void open(const char* path, const unsigned int flags, const mdb_mode_t mode);
    void close() noexcept;

    int get_info(MDB_envinfo* info);
    int get_flags(unsigned int* flags);
    int get_mapsize(size_t* size);
    int get_max_keysize(void);
    int get_max_readers(unsigned int* count);

    int set_flags(const unsigned int flags, const bool onoff = true);
    int set_mapsize(const size_t size);
    int set_max_dbs(const unsigned int count);
    int set_max_readers(const unsigned int count);
    int sync(const bool force = true);

    std::unique_ptr<Transaction> begin_transaction(unsigned int flags = 0);
    std::unique_ptr<Transaction> begin_ro_transaction(unsigned int flags = 0);
    std::unique_ptr<Transaction> begin_rw_transaction(unsigned int flags = 0);

    boost::signals2::signal<void(void)>
        signal_on_before_close_;  // Signals connected transactions that this env is about to close
};

/**
 * MDB_txn wrapper
 */
class Transaction {
   private:
    static MDB_txn* open_transaction(Environment* parent_env, MDB_txn* parent_txn, unsigned int flags = 0);

    friend class Table;

    Environment* parent_env_;  // Pointer to env this transaction belongs to
    MDB_txn* handle_;          // This transaction lmdb handle
    unsigned int flags_;       // Flags this transaction has been opened with

    bool assert_handle(bool should_throw = true);  // Ensures handle_ is validly created

    /*
     * A dbi is an unsigned int handle to a table in database.
     * Opening dbi(s) is required to get access to cursors but handle is
     * valid environment wise. Open dbi on demand when required access to
     * a cursor and keep a map of handles internally. Closing of dbis is not
     * apparently not needed.
     * Key -> the name of the named db
     * Val -> the MDB_dbi handle
     */

    /*
    * Andrea Lanfranchi
    * I originally created a map of opened dbi(s) to persist the binding
    * of a table name with its handle_. This however is incorrect as the
    * handle_ is not an ordinal position rather an opened "slot" within
    * the transaction. LMDB already takes care to keep a list of free
    * slots to use for opening so this additional map is totally
    * redundant. See for reference
    * https://github.com/torquem-ch/lmdb/blob/mdb.master/libraries/liblmdb/mdb.c#L10797-L10810
    * Keep the following line commented for reference
    */
    //std::map<std::string, MDB_dbi> dbis_;  // Collection of opened MDB_dbi

    MDB_dbi open_dbi(const char* name, unsigned int flags = 0);

    boost::signals2::connection conn_on_env_close_;  // Holds the connection to env signal_on_before_close_

   public:
    explicit Transaction(Environment* parent, unsigned int flags = 0);
    Transaction(Environment* parent, MDB_txn* txn, unsigned int flags);
    ~Transaction();

    MDB_txn** handle() { return &handle_; }
    size_t get_id(void);

    bool is_ro(void);  // Whether this transaction is readonly

    // Opens a "named" table or eventually - if name is null - main dbi with handle_ == 1
    std::unique_ptr<Table> open(const TableConfig& config, unsigned flags = 0);

    // This override allows opening of dbi 0 or 1 only which are reserved
    // dbi 0 : FREE_DBI
    // dbi 1 : MAIN_DBI
    std::unique_ptr<Table> open(MDB_dbi dbi);

    Transaction(const Transaction& src) = delete;
    Transaction& operator=(const Transaction& src) = delete;
    Transaction(Transaction&& rhs) = delete;
    Transaction& operator=(Transaction&& rhs) = delete;

    boost::signals2::signal<void(void)>
        signal_on_before_abort_;  // Signals to connected Tables that the transaction is about to abort
    boost::signals2::signal<void(void)>
        signal_on_before_commit_;  // Signals to connected Tables that the transaction is about to commit

    void abort(void);
    int commit(void);
};

/**
 * A table is an hybrid which wraps both an MDB_dbi
 * and an MDB_cursor
 */
class Table {
   public:
    explicit Table(Transaction* parent, MDB_dbi dbi, const char * name);
    ~Table();

    /*
     * MDB_dbi interfaces
     */
    int get_flags(unsigned int* flags);  // Returns the flags used to open the table
    int get_stat(MDB_stat* stat);        // Returns stat info about the table
    int get_rcount(size_t* count);       // Returns the number of records held in table
    std::string get_name(void);          // Returns the name of the table
    MDB_dbi get_dbi(void);               // Returns the ordinal id of the table

    // https://github.com/ledgerwatch/lmdb-go/blob/master/lmdb/mdb.c#L10004
    int clear();  // Removes all contents from the table (cursor is invalidated)
    int drop();   // Deletes the table from the environment (cursor is invalidated)

    /** @brief Gets the value by key. A nil optional is returned if the key is not found.
     *
     * Warning: The memory pointed to by the returned view is owned by the database.
     * The caller may not modify it in any way.
     * Views returned from the database are valid only until a subsequent update operation,
     * or the end of the transaction.
     */
    std::optional<ByteView> get(ByteView key);

    /* Same as the above, but for MDB_DUPSORT data items starting with a given sub_key.
     * Returned values are stripped of the sub_key prefix.
     *
     * See the memory warning above.
     */
    std::optional<ByteView> get(ByteView key, ByteView sub_key);

    /** @brief Deletes an entry.
     * Doesn't do anything if the item is not present.
     */
    void del(ByteView key);

    /* Same as the above, but for MDB_DUPSORT data item that starts with a given sub_key.
     * Doesn't do anything if the item is not present.
     */
    void del(ByteView key, ByteView sub_key);

    /*
     * MDB_cursor interfaces
     */

    std::optional<db::Entry> seek(ByteView prefix);  // Position cursor to first key >= of given prefix
    int seek(MDB_val* key, MDB_val* data);           // Position cursor to first key >= of given key
    int seek_exact(MDB_val* key, MDB_val* data);     // Position cursor to key == of given key
    int get_current(MDB_val* key, MDB_val* data);    // Gets data from current cursor position
    int del_current(bool alldupkeys = false);  // Delete key/data pair at current cursor position. alldupkeys may be set
                                               // true only for tables opened MDB_DUPSORT flag and in that case all
                                               // records with same key are deleted too
    int get_first(MDB_val* key, MDB_val* data);  // Move cursor at first item in table
    int get_prev(MDB_val* key, MDB_val* data);   // Move cursor at previous item in table
    int get_next(MDB_val* key, MDB_val* data);   // Move cursor at next item in table
    int get_last(MDB_val* key, MDB_val* data);   // Move cursor at last item in table
    int get_dcount(size_t* count);               // Returns the count of duplicates at current position

    /** @brief Stores key/data pairs into the database using cursor.
     *
     * The cursor is positioned at the new item, or on failure usually near it.
     * For more fine grained options see #put_current(), #put_nodup, #put_noovrw,
     * #put_reserve(), #put_append(), #put_append_dup() and #put_multiple()
     */
    void put(ByteView key, ByteView data);

    /** @brief Replace the k/d pair at current cursor position
     *
     * The key parameter must be provided and must match the one at current cursor position
     * If env has MDB_DUPSORT the data item must still sort into the same place.
     * This is intended to be used when the new data is the same size as the old, otherwise
     * it will simply perform a delete of the old record followed by an inster
     */
    int put_current(MDB_val* key, MDB_val* data);

    /** @brief Inserts the new k/d pair only if it does not already appear in database
     *
     * This operation may only be invoked if the database was opened with MDB_DUPSORT
     * Function will return MDB_KEYEXISTS if the k/v data pair already appears in the
     * database.
     */
    int put_nodup(MDB_val* key, MDB_val* data);

    /** @brief Inserts the new k/v pair only if it does not already appear in database
     *
     * Function will return MDB_KEYEXISTS if the k/d data pair already appears in the
     * database even if the database supports duplicates (MDB_DUPSORT)
     */
    int put_noovrw(MDB_val* key, MDB_val* data);

    /** @brief Reserves space for data of giben size but doesn't copy data.
     *
     * Function must NOT be used if the database was opened with MDB_DUPSORT
     */
    int put_reserve(MDB_val* key, MDB_val* data);

    /** @brief Append the given k/d pair to the end of the database.
     *
     * No key comparisons are performed. This function allows fast bulk loading
     * when keys are already known to be in the correct order. Loading unsorted
     * keys by this function will cause a MDB_KEYEXIST error.
     */
    int put_append(MDB_val* key, MDB_val* data);

    /** @brief Append the given k/d pair to the end of the database.
     *
     * No key comparisons are performed. This function allows fast bulk loading
     * when keys are already known to be in the correct order. Loading unsorted
     * keys by this function will cause a MDB_KEYEXIST error.
     * Use this function for SORTED dup data.
     */
    int put_append_dup(MDB_val* key, MDB_val* data);

    /** @brief Stores multiple contiguous data elements in a single request
     *
     * This function may only be used if the database was opened with MDB_DUPFIXED
     * The data argument MUST be an array of TWO MDB_val.
     * First MDB_val must be as :
     * - mv_size the size of a single data element
     * - mv_data pointer to the beginning of first data element
     * Second MDB_val must be as :
     * - mv_size the number of data elements to store
     * - mv_data can be anything as it is ignored
     *
     * On return of the function the 2ND MDB_val.mv_size will hold the number
     * of elements effectively written.
     */
    int put_multiple(MDB_val* key, MDB_val* data);

    void close(void);  // Close the cursor (not the dbi) and frees the handle
    bool is_opened(void) { return handle_ != nullptr; }

   private:
    static MDB_cursor* open_cursor(Transaction* parent, MDB_dbi dbi);
    Table(Transaction* parent, MDB_dbi dbi, const char * name, MDB_cursor* cursor);

    int get(MDB_val* key, MDB_val* data,
            MDB_cursor_op operation);  // Gets data by cursor on behalf of operation
    int put(MDB_val* key, MDB_val* data,
            unsigned int flag);  // Puts data by cursor on behalf of operation

    Transaction* parent_txn_;  // The transaction this table belongs to
    MDB_dbi dbi_;              // The underlying MDB_dbi handle for this instance
    std::string name_;         // The name of the dbi
    bool dbi_dropped_{false};  // Whether or not this table has been dropped
    MDB_cursor* handle_;       // The underlying MDB_cursor for this instance

    bool assert_handle(bool should_throw = true);  // Ensures handle_ is validly created

    boost::signals2::connection conn_on_txn_abort_;   // Holds the connection to txn signal_on_before_abort_
    boost::signals2::connection conn_on_txn_commit_;  // Holds the connection to txn signal_on_before_commit_
};

std::shared_ptr<Environment> get_env(const char* path, options opts = {});

}  // namespace silkworm::lmdb

#endif  // SILKWORM_DB_CHAINDB_H_
