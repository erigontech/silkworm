# Silkworm development tools

## Check Log Indices

### Overview

Silkworm maintains transaction log address/topic indices in MDBX database. Such indices are generated at runtime by processing
transaction logs.

### The `check_log_indices` tool

The `check_log_indices` tool is a command-line utility to check the consistency and integrity of transaction log indices.

#### Synopsis

#### Examples

Check only log address index from block 0 up to block 2'000'000

```
check_log_indices --to 2000000 --index address
```

Check only log topic index for block 2'000'000

```
check_log_indices --from 2000000 --to 2000000 --index topic
```

Check both log address and topic indices for block 17'500'000

```
check_log_indices --from 17500000 --to 17500000
```

Check both log address and topic indices from block 17'000'000 up to the tip (beware: long-running)

```
check_log_indices --from 17000000
```

## Snapshots

### Overview

Silkworm stores historical chain data in `snapshots` (immutable .seg files) which maintain binary compatibility with Erigon ones
and can be seeded/downloaded by [BitTorrent](https://en.wikipedia.org/wiki/BitTorrent) protocol.

Each `snapshot` contains just one type of data (e.g. block headers, block bodies, block transactions) encoded with specific format.

A `torrent` is a file format for data transfer (similar to other archive file formats, e.g. zip).  Inside a .torrent file there is a set of information that helps your BitTorrent client find and download data.
This information is a group of files that includes names, sizes, and folder structure. Along with information about files, a .torrent file also contains a list of trackers.

A `magnet link` is a simple text link that includes all the necessary information to download a torrent file.

### The `snapshots` tool

The `snapshots` tool is a collection of small utilities and benchmark tests for working with Silkworm snapshot files.

#### Synopsis

```
Snapshots toolbox
Usage: snapshots [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  --tool ENUM:{count_headers->0,decode_segment->1,download->2}:ENUM in [0 - 2] [2] 
                              The snapshot tool to use
  --repetitions INT:INT in [1 - 100] [1] 
                              The test repetitions
  --file TEXT [v1-000000-000500-bodies.seg] 
                              The path to snapshot file
  --page INT:INT in [1 - 1024] [4096] 
                              The page size in kB
  --torrent_dir TEXT [.torrent] 
                              The path to torrent file repository
  --magnet TEXT               The magnet link to download
  --magnet_file TEXT [.magnet_links] 
                              The file containing magnet links to download
  --download_rate_limit INT:INT in [4194304 - 134217728] [67108864] 
                              The download rate limit in bytes per second
  --upload_rate_limit INT:INT in [1048576 - 33554432] [4194304] 
                              The upload rate limit in bytes per second
  --active_downloads INT:INT in [3 - 20] [6] 
                              The max number of downloads active simultaneously
[Option Group: Log]
  Logging options
  Options:
    --log.verbosity ENUM:{critical->1,debug->5,error->2,info->4,trace->6,warning->3}:ENUM in [1 - 6] [4] 
                                Sets log verbosity
    --log.stdout                Outputs to std::out instead of std::err
    --log.nocolor               Disable colors on log lines
    --log.utc                   Prints log timings in UTC
    --log.threads               Prints thread ids
    --log.file TEXT             Tee all log lines to given file name

```

Currently available tools are:
- `count_bodies`
- `count_headers`
- `create_index`
- `open_index`
- `decode_segment`
- `download`
- `lookup_header`
- `lookup_body`
- `lookup_txn`
- `sync`

#### Examples

Download one snapshot from its magnet link and put it in torrent folder:

```
snapshots --tool download --magnet "magnet:?xt=urn:btih:83112dec4bec180cff67e01d6345c88c3134fd26&dn=v1-014500-015000-transactions.seg&tr=udp%3a%2f%2ftracker.opentrackr.org%3a1337%2fannounce&tr=udp%3a%2f%2f9.rarbg.com%3a2810%2fannounce&tr=udp%3a%2f%2ftracker.openbittorrent.com%3a6969%2fannounce&tr=http%3a%2f%2ftracker.openbittorrent.com%3a80%2fannounce&tr=https%3a%2f%2fopentracker.i2p.rocks%3a443%2fannounce&tr=udp%3a%2f%2fopen.stealth.si%3a80%2fannounce&tr=udp%3a%2f%2ftracker.torrent.eu.org%3a451%2fannounce&tr=udp%3a%2f%2ftracker.tiny-vps.com%3a6969%2fannounce&tr=udp%3a%2f%2ftracker.pomf.se%3a80%2fannounce&tr=udp%3a%2f%2ftracker.dler.org%3a6969%2fannounce&tr=udp%3a%2f%2fopen.demonii.com%3a1337%2fannounce&tr=udp%3a%2f%2fexplodie.org%3a6969%2fannounce&tr=udp%3a%2f%2fexodus.desync.com%3a6969%2fannounce&tr=https%3a%2f%2ftracker.nanoha.org%3a443%2fannounce&tr=https%3a%2f%2ftracker.lilithraws.org%3a443%2fannounce&tr=https%3a%2f%2ftr.burnabyhighstar.com%3a443%2fannounce&tr=http%3a%2f%2ftracker.mywaifu.best%3a6969%2fannounce&tr=http%3a%2f%2fbt.okmp3.ru%3a2710%2fannounce&tr=udp%3a%2f%2fzecircle.xyz%3a6969%2fannounce&tr=udp%3a%2f%2fyahor.ftp.sh%3a6969%2fannounce"
```

Download all snapshots from the magnet links contained in magnet file and put them in torrent folder:

```
snapshots --tool download --magnet_file .magnet_links --log.verbosity debug --active_downloads 3
```

Count how many block headers are present in header snapshots under torrent folder:

```
snapshots --tool count_headers --repetitions 1 --log.verbosity info
```

Create indexes for target snapshot under torrent folder:

```
snapshots --tool create_index --file v1-000000-000500-headers.seg --log.verbosity info
```

Search block header by number in one snapshot

```
snapshots --tool lookup_header --snapshot_file v1-001500-002000-headers.seg --number 1500013
```

Search block body by number in all snapshots

```
snapshots --tool lookup_body --number 1500012
```

Search block body by number in one snapshot

```
snapshots --tool lookup_body --snapshot_file v1-001500-002000-bodies.seg --number 1500012
```

Search transaction by hash in all snapshots

```
snapshots --tool lookup_txn --hash 0x3ba9a1f95b96d0a43093b1ade1174133ea88ca395e60fe9fd8144098ff7a441f
```

Search transaction by hash or by progressive identifier in one snapshot

```
snapshots --tool lookup_txn --snapshot_file v1-001500-002000-transactions.seg --hash 0x3ba9a1f95b96d0a43093b1ade1174133ea88ca395e60fe9fd8144098ff7a441f
snapshots --tool lookup_txn --snapshot_file v1-001500-002000-transactions.seg --number 7341272
```

## gRPC Toolbox

### Overview

Silkworm RPCDaemon may run in standalone mode using gRPC interfaces to communicate to other components.

### The `grpc_toolbox` tool

The `db_toolbox` tool is a collection of utilities to query the KV/ETHBACKEND gRPC interface of Erigon/Silkworm.

#### Synopsis

#### Examples

Print the number of timestamps in which the specified account has changed state

```
grpc_toolbox kv_index_range --table AccountsHistoryIdx --key 0x616a3E55a20dD54CC9fBb63D8333D89c275c9D90
```

Print the first 10 changes in account state history using verbose mode (i.e. print keys and values)

```
grpc_toolbox kv_history_range --table AccountsHistory --limit 10 --verbose
```

Print the first 10 changes in account state for the specified key range using verbose mode (i.e. print keys and values)

```
grpc_toolbox kv_domain_range --table accounts --from_key 0x616a3E55a20dD54CC9fBb63D8333D89c275c9D90 \
--to_key 0x716a3E55a20dD54CC9fBb63D8333D89c275c9D90 --timestamp 100000000 --limit 10 --verbose
```
