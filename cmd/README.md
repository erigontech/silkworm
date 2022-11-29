# Silkworm tools

## Snapshots

### Overview

Historical data are stored in `snapshots` (immutable .seg files) seeded/downloaded by [BitTorrent](https://en.wikipedia.org/wiki/BitTorrent) protocol.

Each `snapshot` contains just one type of data (e.g. block headers, block bodies, block transactions) encoded with specific format.

A `torrent` is a file format for data transfer (similar to other archive file formats, e.g. zip).  Inside a .torrent file there is a set of information that helps your BitTorrent client find and download data.
This information is a group of files that includes names, sizes, and folder structure. Along with information about files, a .torrent file also contains a list of trackers.

A `magnet link` is a simple text link that includes all the necessary information to download a torrent file.

### The `snapshots` tool

The `snapshots` tool is a collection of small utilities and benchmark tests for working with snapshot files.

#### Synopsis

```
Snapshots toolbox
Usage: cmd/snapshots [OPTIONS]

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
- `count_headers`
- `decode_segment`
- `download`

#### Examples

Download one snapshot from its magnet link and put it in torrent folder:

```
cmd/snapshots --tool download --magnet "magnet:?xt=urn:btih:83112dec4bec180cff67e01d6345c88c3134fd26&dn=v1-014500-015000-transactions.seg&tr=udp%3a%2f%2ftracker.opentrackr.org%3a1337%2fannounce&tr=udp%3a%2f%2f9.rarbg.com%3a2810%2fannounce&tr=udp%3a%2f%2ftracker.openbittorrent.com%3a6969%2fannounce&tr=http%3a%2f%2ftracker.openbittorrent.com%3a80%2fannounce&tr=https%3a%2f%2fopentracker.i2p.rocks%3a443%2fannounce&tr=udp%3a%2f%2fopen.stealth.si%3a80%2fannounce&tr=udp%3a%2f%2ftracker.torrent.eu.org%3a451%2fannounce&tr=udp%3a%2f%2ftracker.tiny-vps.com%3a6969%2fannounce&tr=udp%3a%2f%2ftracker.pomf.se%3a80%2fannounce&tr=udp%3a%2f%2ftracker.dler.org%3a6969%2fannounce&tr=udp%3a%2f%2fopen.demonii.com%3a1337%2fannounce&tr=udp%3a%2f%2fexplodie.org%3a6969%2fannounce&tr=udp%3a%2f%2fexodus.desync.com%3a6969%2fannounce&tr=https%3a%2f%2ftracker.nanoha.org%3a443%2fannounce&tr=https%3a%2f%2ftracker.lilithraws.org%3a443%2fannounce&tr=https%3a%2f%2ftr.burnabyhighstar.com%3a443%2fannounce&tr=http%3a%2f%2ftracker.mywaifu.best%3a6969%2fannounce&tr=http%3a%2f%2fbt.okmp3.ru%3a2710%2fannounce&tr=udp%3a%2f%2fzecircle.xyz%3a6969%2fannounce&tr=udp%3a%2f%2fyahor.ftp.sh%3a6969%2fannounce"
```

Download all snapshots from the magnet links contained in magnet file and put them in torrent folder:

```
cmd/snapshots --tool download --magnet_file .magnet_links --log.verbosity 5 --active_downloads 3
```

Count how many block headers are present in header snapshots under torrent folder:

```
cmd/snapshots --tool count_headers --repetitions 1 --log.verbosity 4
```
