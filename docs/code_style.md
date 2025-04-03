# Silkworm code style

The codebase respects:
1. [C++ Core Guidelines][cpp-core-guidelines]
1. [Google's C++ Style Guide][cpp-google-style-guide] with amendments (see below)
1. [clang-format](https://clang.llvm.org/docs/ClangFormat.html) rules according to our .clang-format config
1. [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) checks according to our .clang-tidy config

This is enforced by tools and code reviews.

clang-format runs on CI for each PR as a part of "lint" job. It can be run locally using `make fmt`.

clang-tidy runs on CI when a PR is merged to `master` as a part of integration workflow. The report is attached to the "ARTIFACTS" section of the linux-clang-tidy job that can be found [here](https://app.circleci.com/pipelines/github/erigontech/silkworm?branch=master).

## Extra guidelines

This is a list of project-specific guidelines that take precedence over the rules defined elsewhere.

### Basic rules

1. .cpp & .hpp file extensions for C++; .c & .h are reserved for C.
1. Maximum line length is 120, indentation is 4 spaces. Use `make fmt` to reformat according to the code style.
1. Every code file starts with the Apache license boilerplate. Use `make lint` to check this.
1. Use `#pragma once` in the headers instead of the classic `#ifndef` guards.
1. Use `snake_case()` for function names.
1. Exceptions are allowed outside of the `core` library.
1. `using namespace foo` is allowed inside .cpp files, but not inside headers.
1. User-defined literals are allowed.
1. `template <Concept T>` syntax is allowed.
1. Use `size_t` without `std::` prefix.  

### Libraries

1. `<filesystem>` is allowed.
1. Usage of coroutines is allowed via [task.hpp](../silkworm/infra/concurrency/task.hpp) inclusion.
1. In addition to the [Boost libraries permitted in the style guide](https://google.github.io/styleguide/cppguide.html#Boost), we allow:
	* Algorithm
	* Asio
	* Circular Buffer
	* DLL
	* Process
	* Signals2
	* System
	* Thread
	* Url

### P1a init syntax convention for variables

Use modern init syntax only for custom construction of objects. Use a more conventional assignment operator primitive values and references.

Good:

	BlockNum expected_blocknum = previous_progress + 1;
	ChainConfig& config = kMainnetConfig;
	ExecutionProcessor processor{block, *rule_set, buffer, *chain_config};

Bad:

	BlockNum expected_blocknum{previous_progress + 1};
	ChainConfig& config{kMainnetConfig};
	ExecutionProcessor processor{block, *rule_set, buffer, *chain_config};

Copy initialization can use either style:

	auto index_path{snapshot_path->index_file()};
	auto index_path = snapshot_path->index_file();

Exception:

	Bytes transaction_key(8, 0);  // has to use parentheses to create 8 zeros instead of [8, 0] list

### P1b init syntax convention for data members (fields)

Member initializer list must use the modern init syntax:

	DebugExecutor(...) :
	    database_reader_{database_reader},
	    block_cache_{block_cache},
	    workers_{workers},
	    tx_{tx},
	    config_{config} {}

as well as inline initialization of data members:

	struct PayloadAttributes {
		uint64_t timestamp{0};
	};

### P2 io_context var naming

Use `ioc` name when having a single variable of type `asio::io_context` (unless having a more specific name brings much more expressiveness).

Good:

	io_context ioc;

Bad:

	io_context io_context;
	io_context context;
	io_context ctx;
	io_context io;

### P3 BlockNum var naming

Use `BlockNum block_num` name when having a single variable of type `BlockNum` (unless having a more specific name brings expressiveness, e.g.: `start`, `end`, `last`). Do not use `height`.

Good:

	BlockNum block_num;

Bad:

	BlockNum height
	BlockNum block_number
	BlockNum number
	BlockNum num
	BlockNum bn
	BlockNum b

### P4 RAII lock type usage

Use `std::scoped_lock` for a common case where a single mutex needs to be locked immediately and unlocked at the end of the scope. Do not use `std::lock_guard`.  
Use `std::unique_lock` where a manual `unlock()` is required, for working with `std::condition_variable` or if other unique_lock features are needed (e.g. deferred locking, adoption).

### P5 SILKWORM_ASSERT

Use `SILKWORM_ASSERT` instead of `assert(x)`.

### P6 SILK_DEBUG logging macros

Use `SILK_DEBUG` logging macros instead of `log::Debug()` syntax.

### P7 explicit keyword

Add explicit keyword, but only for single argument constructors, as per [CppCoreGuidelines C.46](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rc-explicit)

### P8 nodiscard

Do not habitually use `[[nodiscard]]` by default. Use it sparingly as needed.

We've had a "modernize-use-nodiscard" clang-tidy policy, which led to the proliferation of `[[nodiscard]]` throughout the codebase. The policy was disabled, but a lot of usages were redundant. For example, usage on Task is redundant, because the type itself is already marked with `[[nodiscard]]` within the library.

An example where it is useful: if a function has a side effect, and returns no result or an error (e.g. `bool ok = f()`).

### P9 move-only reference parameters

Default to move by value. Use `T&&` parameters with caution.

Legitimate uses are move-constructors. In some other cases it could be seen as a premature optimization.

When copy-prevention is required, consider making a type move-only. If T is an aggregate type (e.g. a basic struct), deleting the copy member functions defeats the aggregate semantics and forces to provide a custom constructor. In this case, if copy-prevention is critical for performance, it might be easier to use `T&&` than providing a custom constructor. 

### P10 constants definition keywords

In all cases the order of keywords is:

	[static] [inline] const[expr]

**Case 1:** For class-member constants:

Use `static constexpr` if possible:

	static constexpr uint64_t kMinDifficulty{0x20000};

(`inline` is implicit in this case),

otherwise use `static inline const`:

	static inline const std::filesystem::path kDefaultTorrentRepoPath{".torrent"};

**Case 2:** For private constants in .cpp files:

Use `static constexpr` if possible,  
otherwise use `static const`.

`inline` is unnecessary in this case.

**Case 3:** For global constants in .hpp files:

Use `inline constexpr` if possible,    
otherwise use `inline const` if possible,  
otherwise use `extern const`.

`static` is misleading in this case.

See also: [Constants: Safe Idioms](https://abseil.io/tips/140)

### P11 CLion code inspections

CLion has some extra code inspections in addition to clang-tidy. These inspections are not enforced. It is up to each developer to decide if they are useful or not (and enable/disable them locally).

### P12 string formatting

Use `<<` (and `std::stringstream`) or `+` syntax as you feel for logs and error messages. `std::format` is not supported, but [planned eventually](https://github.com/erigontech/silkworm/issues/2384).

### P13 include paths and quotes

Use double quotes and paths relative to the current file within a CMake library, allow referring ancestor directories within the library:

	#include "types.hpp"
	#include "../../../api/endpoint/range.hpp"

Otherwise use `<` and paths relative to the silkworm root source directory:

	#include <silkworm/core/common/base.hpp>  // outside core

### P14 io_context vs any_io_executor

Most of the async code needs to dispatch operations (or create sub objects that need to dispatch), and doesn't need to run or stop the io_context. In this case the executor interface is enough. `any_io_executor` is a lightweight copyable and movable type-erased wrapper that can be used to dispatch async work without binding to a concrete executor type (such as `io_context::executor`). Prefer using `any_io_executor` if possible instead of `io_context`.

`any_io_executor` can be passed by value, but clang-tidy usually wants to pass it by a const reference:

	const boost::asio::any_io_executor& executor

### P15 getters in .hpp or .cpp

Put simple single line getters in .hpp:

	int id() const { return id_; }

### P16 i++ vs ++i

Prefer ++i by default. Only use i++ where a previous result value is needed.

Good:

	for (size_t i = 0; i < items.size(); ++i)

Bad:

	for (size_t i = 0; i < items.size(); i++)

See [this guideline](https://google.github.io/styleguide/cppguide.html#Preincrement_and_Predecrement)

### P17 auto for constants

Use an explicit type specification instead of `auto` in constants:

Good:

static constexpr size_t kThreadNameFixedSize = 11;

Bad:

static constexpr auto kThreadNameFixedSize = 11;

### P18a optional for an empty std::function

Sometimes we use `std::function` as a factory or a callback object. If it is optional prefer using `optional<function<T(U)>>` and `nullopt` where null is expected instead of using an empty `std::function` (with a `nullptr` inside).

### P18b optional smart pointers

Sometimes we use `std::unique_ptr/smart_ptr` to delay initialization or for optional subobjects. In this case a null value should be expected. In other cases we `make_unique` in the constructor and the pointer is never null.

Use a default-constructed `std::unique_ptr/smart_ptr` where null is expected.

### P19 name prefix for factory functions

Use `make` name/prefix for factory functions instead of `build` or `create`:

	SentryPtrPair make_sentry(...)
	std::shared_ptr<TimerImpl> make(...)
	std::string make_thread_name(...)

`build` prefix can be used for a “builder” pattern, where it might have no parameters, and potential side effects, for example `RecSplit::build()`.

### P20 to_string method naming

Use `to_string()` by default to convert an object to std::string (e.g. for logging purposes). Only provide `operator<<` if needed (implemented on top of `to_string()`).

If a global function is required, `xxx_to_string()` name should be used.

### P21 multiline parameters indentation

Default to 1 parameter per line.

Accepted styles:

	ValidationResult execute_block(
		const Block& block,
		State& state,
		const ChainConfig& chain_config);

	ValidationResult execute_block(const Block& block,
                                   State& state,
                                   const ChainConfig& chain_config);

The first style is more friendly to Git.
The 2nd style in .cpp files clearly splits the function body from parameters.

Bad:

    void start_new_batch(BlockNum block_height, const evmc::bytes32& block_hash,
                         const std::vector<Bytes>&& tx_rlps, bool unwind);

### P22 trailing comments

Trailing comments are banned.

Good:

	class StateChangeCollection {
		//! The database transaction ID associated with the state changes.
		uint64_t tx_id_{0};
	};

	// Download the torrent files via web seeding from settings.url_seed
	auto web_seed_torrents = download_web_seed(settings);

Bad:

	struct AppOptions {
		std::string datadir{};  // Provided database path
	};

	block1.ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader

### P23 string constants

When defining a string constant prefer `string_view`.

Good:

	constexpr std::string_view kDbDataFileName{"mdbx.dat"};
	constexpr std::string_view kDbDataFileName = "mdbx.dat";

Bad:

	constexpr const char* kPruneModeHistoryKey{"pruneHistory"};
	constexpr const char* kSafeBlockHash = "safeBlockHash";
	static const std::string kHeadBlockHash = "headBlockHash";
	constexpr std::string_view kTorrentExtension{".torrent"sv};

### P24 tmp vs temp naming convention

The word "temporary" should be abbreviated as `tmp`, not `temp`.

Good: 

	TemporaryDirectory tmp_dir;

Bad:

	TempChainData temp_chaindata;

### P25 license boilerplate

Use SPDX short form like in evmone:

	// Copyright 2025 The Silkworm Authors
	// SPDX-License-Identifier: Apache-2.0

### P26 filename vs file name

Use `filename` (and `Filename`) everywhere.

Good:

	fs::path entry_filename = entry.path().stem();
	FilenameFormat format;

Bad:

	std::string get_file_name();
	const char* kSessionFileName{".session"};

### P27 member init list vs constructor body code

Prefer constructors based on member init list.

Use constructor body code if the member init list approach leads to cluttered dense code.
It is possible to unclutter the member init list using static helper functions,
but constructor body code benefit is that it keeps the init sequence in one place.

### P28 Bytes size() vs length()

Prefer `size()` instead of `length()`. The methods are aliases of each other.

### P29 friend vs member comparison operators

Prefer "friend" version of the comparison operators as it is more versatile, and in some cases mandatory (e.g. for using as a key of std::map).

Good:

	friend bool operator==(const Config& lhs, const Config& rhs) = default;

Bad:

	bool operator==(const Config& other) const = default;

### P30 tx vs txn naming

Use "txn", "txns" abbreviations for Ethereum transactions.  
Use "tx", "txs" abbreviations for database transactions.

Good:

	Stage::Result TxnLookup::forward(RWTx& tx)

Bad:

	Stage::Result TxLookup::forward(RWTxn& txn)


[cpp-core-guidelines]: https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines
[cpp-google-style-guide]: https://google.github.io/styleguide/cppguide.html
