# db_toolbox

Silkworm keeps recent chain data in MDBX database for faster access.
The `db_toolbox` tool is a collection of utilities to perform operations on Silkworm MDBX database.

Simple usage is `db_toolbox [OPTIONS] [SUBCOMMAND] [SUBCOMMANDOPTIONS]`

## Examples

Dump the database table layout and stats

```
db_toolbox --datadir ~/Library/Silkworm/ tables
```

Dump the progress of sync stages (i.e. content of SyncStage table)

```
db_toolbox --datadir ~/Library/Silkworm/ stages
```

Clear content (i.e. delete all the rows) in LogAddressIndex and LogTopicIndex tables

```
db_toolbox --datadir ~/Library/Silkworm/ --exclusive clear --names LogAddressIndex LogTopicIndex
```

Reset the LogIndex stage progress to zero

```
db_toolbox --datadir ~/Library/Silkworm/ --exclusive stage-set --name LogIndex --block 0
```

## OPTIONS
Common options always specify the base data file to open :
- `--datadir` which indicates the **directory** path where `data.mdb` is located
- `--lmdb.mapSize` which indicates the **LMDB map size** of data.mdb

### Caveat
LMDB's mapSize value basically indicates the width of the segment of virtual memory that has been assigned a direct byte-for-byte correlation with with the data file on disk. This exhibits a very different behavior amongst Linux OS and Windows OS: while in the first case mapSize value behaves as a "limit" for the data file growth, on Windows there is a 1:1 relation amongst mapSize value and the effective size on disk. Put in other words : if, on Linux, we open a **new** LMDB data file specifying 10GB mapSize, we will have a data file with an effective size of few bytes until we begin to insert new data and eventually the growth of file size is limited by mapSize value (i.e. the file won't grow beyond 10GB and any attempt to insert new data will return an `MDB_MAPFULL` error). On Windows instead, the opening of a **new** LMDB data file with 10GB mapSize will result in the immediate allocation on disk of a file sized 10GB. 

### Hint
Omitting the specification of --lmdb.mapSize is allowed as long as the data file already exists on disk. In such case the value is automatically adjusted to the size of data.mdb. This is like specifying an `lmdb.mapSize == 0`.
**Warning** : although db_toolbox protects against errors is highly discouraged to provide a value for --lmdb.mapSize lower than actual file size cause, as observed behavior, the result is a truncation of data file to a size matching --lmdb.mapSize thus causing the invalidation of all mappings for existing data.

# Subcommand : tables
Usage `db_toolbox --datadir <parent-directory-to-data.mdb> tables`

This subcommand requires no additional arguments and provides a detailed list of tables stored into data.mdb.
Here is a sample output:
```
 Database tables    : 40
 Database page size : 4096

 Dbi Table name                  Records  D     Branch       Leaf   Overflow         Size
 --- ------------------------ ---------- -- ---------- ---------- ---------- ------------
   0 [FREE_DBI]                     1298  2          1         38       2662     11063296
   1 [MAIN_DBI]                       38  1          0          1          0         4096
   2 ACS                               0  0          0          0          0            0
   3 B                                 0  0          0          0          0            0
   4 CODE                         332167  4        551      36369     471560   2082734080
   5 CST2                      480725185  5      42626    2983648          0  12395618304
   6 DBINFO                            4  1          0          1          0         4096
   7 DatabaseVersion                   1  1          0          1          0         4096
   8 H                          11093179  4       2888     183237          0    762368000
   9 LastBlock                         1  1          0          1          0         4096
  10 LastFast                          1  1          0          1          0         4096
  11 LastHeader                        1  1          0          1          0         4096
  12 PLAIN-ACS                  11093083  4       2206     636977   13858850  59383943168
  13 PLAIN-CST2                480725185  5      23356    2423015          0  10020335616
  14 PLAIN-SCS                   8060176  4       1199     345971   19021260  79333089280
  15 PLAIN-contractCode         28925348  5      10217     727455          0   3021504512
  16 SCS                               0  0          0          0          0            0
  17 SNINFO                            0  0          0          0          0            0
  18 SSP2                             13  1          0          1          0         4096
  19 SSU2                             12  1          0          1          0         4096
  20 TrieSync                          0  0          0          0          0            0
  21 b                          11093154  5       7247     579534   44431570 184395165696
  22 call_from_index                   0  0          0          0          0            0
  23 call_to_index                     0  0          0          0          0            0
  24 clique-                           0  0          0          0          0            0
  25 contractCode               20079491  5      13292     647684          0   2707357696
  26 ethereum-config-                  1  1          0          1          0         4096
  27 h                          33279441  5      24581    2054802          0   8517152768
  28 hAT                       139283444  5      70658    3774220     657381  18441252864
  29 hST                       468672601  6     190311   10240434     472990  44661698560
  30 iB                                0  0          0          0          0            0
  31 iTh2                      161166225  4       4472     585499          0   2416521216
  32 incarnationMap             10390653  4       1487     140197          0    580337664
  33 l                         874122311  5     210798   10736097          0  44838481920
  34 log_address_index           2922721  4        870      91062     157358   1021091840
  35 log_topic_index           102732305  5      54006    3118356     259925  14058647552
  36 migrations                       10  1          0          1          0         4096
  37 r                          11093083  4       5655     452366   42411330 175592861696
  38 secure-key-                       0  0          0          0          0            0
  39 txSenders                   9553003  5      17663    1412848    4982030  26265767936

 Database map size    :  773094113280
 Size of file on disk :  773094113280
 Data pages count     :     168580819
 Data pages size      :  690507034624
 Reclaimable pages    :       1335698
 Reclaimable size     :    5471019008
 Free space available :   88058097664
```

Each table reports:
- the id it was opened with
- the name
- the number of records stored
- the maximum depth of the Btree
- The **number of pages** for Branch, Leaf and Overflow
- The overall size of data stored which is `(Branch + Leaf + Overflow) * Database page size`

The bottom part of the report depicts the storage status of the data file.

# Subcommand : freelist
Usage `db_toolbox --datadir <parent-directory-to-data.mdb> freelist [--detail]`

This produces as output the sum of reclaimable space held in FREE_DBI.
Sample :
```
 Total free pages     :       1335698
 Total free size      :    5471019008
```
When the `--detail` CLI flag is also provided, the output records the free reclaimable datapages for each transaction which have freed some.
Sample :
```
     TxId     Pages         Size
--------- --------- ------------
    33133       263      1077248
    33134       509      2084864
    33135       509      2084864
    33136       509      2084864
    33137       509      2084864
    33138       509      2084864
    33139       509      2084864
    33140       509      2084864
    33141       509      2084864
    33142       509      2084864
    33143       509      2084864
    33144       509      2084864
    33145       509      2084864
    33146       509      2084864
    33147       509      2084864
    33148       509      2084864
    33149       509      2084864
    33150       509      2084864
    33151       509      2084864
    33152       509      2084864
    33153       509      2084864
    33154       509      2084864
    33155       509      2084864
    33156       509      2084864
    33157       509      2084864
    [ ... ]
    34419       288      1179648
    34420         6        24576
    34421     12157     49795072
    34422         6        24576
    34423        15        61440
    34424         6        24576
    34425        12        49152
    34426         6        24576
    34427         6        24576
    34428        59       241664
    34429         6        24576
    34430      9569     39194624

 Total free pages     :       1335698
 Total free size      :    5471019008
```

# Subcommand : clear
Usage `db_toolbox --datadir <parent-directory-to-data.mdb> clear --names <list-of-table-names> [--drop]`

This command provides a handy way to empty a table from all records or drop it.

Example :
`db_toolbox --datadir <parent-directory-to-data.mdb> clear --names h b`

will delete all records from tables `h` and `b` but the table (meant as a container) will remain into database.

Example :
`db_toolbox --datadir <parent-directory-to-data.mdb> clear --names h b --drop`

will delete tables `h` and `b` from database just like a SQL `drop` statement.

## Caveat
Like all operations on LMDB the deletion of records (or of an entire table) lives within a writable transaction and by consequence requires database file to have enough space available to record all data pages which will be freed by the transaction. This implies the size of database file may grow.

# Subcommand : compact
Usage `db_toolbox --datadir <parent-directory-to-data.mdb> compact --workdir <parent-directory-to-compacted-data.mdb> [--replace] [--nobak]`

The purpose of this subcommand is to obtain a _compacted_ data file. The compaction process renumbers all data pages while reclaiming those previously freed by preceding transactions. This command is the implementation of `mdb_env_copy2` LMDB API call with `MDB_CP_COMPACT` flag. 
Running this command reports no progress and, ad indicative figure, took more than 6 hours to compact an 730GB data file on Windows with NMVe storage support.
Additional flag `--replace` will replace origin data file with compacted one by renaming original data file with `.bak` suffix.
Eventually flag `--nobak` will prevent the creation of the bak copy and directly overwrites the origin file.

This is a sample output of `tables` command **before** a compact action
```
 Database tables    : 40
 Database page size : 4096

 Dbi Table name                  Records  D     Branch       Leaf   Overflow         Size
 --- ------------------------ ---------- -- ---------- ---------- ---------- ------------
   0 [FREE_DBI]                     1298  2          1         38       2662     11063296
   1 [MAIN_DBI]                       38  1          0          1          0         4096
   2 ACS                               0  0          0          0          0            0
   3 B                                 0  0          0          0          0            0
   4 CODE                         332167  4        551      36369     471560   2082734080
   5 CST2                      480725185  5      42626    2983648          0  12395618304
   6 DBINFO                            4  1          0          1          0         4096
   7 DatabaseVersion                   1  1          0          1          0         4096
   8 H                          11093179  4       2888     183237          0    762368000
   9 LastBlock                         1  1          0          1          0         4096
  10 LastFast                          1  1          0          1          0         4096
  11 LastHeader                        1  1          0          1          0         4096
  12 PLAIN-ACS                  11093083  4       2206     636977   13858850  59383943168
  13 PLAIN-CST2                480725185  5      23356    2423015          0  10020335616
  14 PLAIN-SCS                   8060176  4       1199     345971   19021260  79333089280
  15 PLAIN-contractCode         28925348  5      10217     727455          0   3021504512
  16 SCS                               0  0          0          0          0            0
  17 SNINFO                            0  0          0          0          0            0
  18 SSP2                             13  1          0          1          0         4096
  19 SSU2                             12  1          0          1          0         4096
  20 TrieSync                          0  0          0          0          0            0
  21 b                          11093154  5       7247     579534   44431570 184395165696
  22 call_from_index                   0  0          0          0          0            0
  23 call_to_index                     0  0          0          0          0            0
  24 clique-                           0  0          0          0          0            0
  25 contractCode               20079491  5      13292     647684          0   2707357696
  26 ethereum-config-                  1  1          0          1          0         4096
  27 h                          33279441  5      24581    2054802          0   8517152768
  28 hAT                       139283444  5      70658    3774220     657381  18441252864
  29 hST                       468672601  6     190311   10240434     472990  44661698560
  30 iB                                0  0          0          0          0            0
  31 iTh2                      161166225  4       4472     585499          0   2416521216
  32 incarnationMap             10390653  4       1487     140197          0    580337664
  33 l                         874122311  5     210798   10736097          0  44838481920
  34 log_address_index           2922721  4        870      91062     157358   1021091840
  35 log_topic_index           102732305  5      54006    3118356     259925  14058647552
  36 migrations                       10  1          0          1          0         4096
  37 r                          11093083  4       5655     452366   42411330 175592861696
  38 secure-key-                       0  0          0          0          0            0
  39 txSenders                   9553003  5      17663    1412848    4982030  26265767936

 Database map size    :  773094113280
 Size of file on disk :  773094113280
 Data pages count     :     168580819
 Data pages size      :  690507034624
 Reclaimable pages    :       1335698
 Reclaimable size     :    5471019008
 Free space available :   88058097664
```

And this is the same database **after** a compaction (6 hours and 10 minutes later)
```
 Database tables    : 40
 Database page size : 4096

 Dbi Table name                  Records  D     Branch       Leaf   Overflow         Size
 --- ------------------------ ---------- -- ---------- ---------- ---------- ------------
   0 [FREE_DBI]                        0  0          0          0          0            0
   1 [MAIN_DBI]                       38  1          0          1          0         4096
   2 ACS                               0  0          0          0          0            0
   3 B                                 0  0          0          0          0            0
   4 CODE                         332167  4        551      36369     471560   2082734080
   5 CST2                      480725185  5      42626    2983648          0  12395618304
   6 DBINFO                            4  1          0          1          0         4096
   7 DatabaseVersion                   1  1          0          1          0         4096	
   8 H                          11093179  4       2888     183237          0    762368000
   9 LastBlock                         1  1          0          1          0         4096
  10 LastFast                          1  1          0          1          0         4096
  11 LastHeader                        1  1          0          1          0         4096
  12 PLAIN-ACS                  11093083  4       2206     636977   13858850  59383943168
  13 PLAIN-CST2                480725185  5      23356    2423015          0  10020335616
  14 PLAIN-SCS                   8060176  4       1199     345971   19021260  79333089280
  15 PLAIN-contractCode         28925348  5      10217     727455          0   3021504512
  16 SCS                               0  0          0          0          0            0
  17 SNINFO                            0  0          0          0          0            0
  18 SSP2                             13  1          0          1          0         4096
  19 SSU2                             12  1          0          1          0         4096
  20 TrieSync                          0  0          0          0          0            0
  21 b                          11093154  5       7247     579534   44431570 184395165696
  22 call_from_index                   0  0          0          0          0            0
  23 call_to_index                     0  0          0          0          0            0
  24 clique-                           0  0          0          0          0            0
  25 contractCode               20079491  5      13292     647684          0   2707357696
  26 ethereum-config-                  1  1          0          1          0         4096
  27 h                          33279441  5      24581    2054802          0   8517152768
  28 hAT                       139283444  5      70658    3774220     657381  18441252864
  29 hST                       468672601  6     190311   10240434     472990  44661698560
  30 iB                                0  0          0          0          0            0
  31 iTh2                      161166225  4       4472     585499          0   2416521216
  32 incarnationMap             10390653  4       1487     140197          0    580337664
  33 l                         874122311  5     210798   10736097          0  44838481920
  34 log_address_index           2922721  4        870      91062     157358   1021091840
  35 log_topic_index           102732305  5      54006    3118356     259925  14058647552
  36 migrations                       10  1          0          1          0         4096
  37 r                          11093083  4       5655     452366   42411330 175592861696
  38 secure-key-                       0  0          0          0          0            0
  39 txSenders                   9553003  5      17663    1412848    4982030  26265767936

 Database map size    :  750808727552
 Size of file on disk :  750808682496
 Data pages count     :     168578118
 Data pages size      :  690495971328
 Reclaimable pages    :             0
 Reclaimable size     :             0
 Free space available :   60312756224
```

## Caveat
To run the compact action you need free storage space available at least equal to size of origin data file.
Please note that this tool does reclaim free space **but does not defragment** tables segments.

# Subcommand : copy
This tools gives the user the ability to copy individual table(s) from one database to another instead of keeping copies of entire databases.

Usage 
```
db_toolbox --datadir <parent-directory-to-source-data.mdb> copy --targetdir <parent-directory-to-target-data.mdb> \
         [--create --new.mapSize <value>] [--tables <list-of-table-names-to-copy>] \
         [--noempty] [--upsert] [--commit]
```
where 
- `--targetdir` specifies the target directory holding the target data.mdb (directory must exist)
- if target data.mdb does not exist (i.e. target directory is empty) must specify `--create` and `--new.mapSize` with the initial map size for the data file being created
- `--tables` specifies a list of table names to copy. If omitted all **known** tables (see below) from origin data file will be copied
- `--noempty` flag specifies origin empty tables must not be copied (i.e. they're not created on target)
- `--upsert` flag forces the tool to copy origin data into target using Upserts instead of Appends. This is necessary when target db already exists and already contains populated tables with identical name
- `--commit` specifies the weight of each commit. By default the copy action commits every 5GB.

**Limitation to known tables** : due to the nature of copy action the tool **must know** in advance the _definition_ of origin and target table (for example if is DUPSORTed) and by consequence all tables which do not have a definition in Turbo-Geth (and in Silkworm) code will be skipped.

This tool automatically enlarges data file on behalf of the amount of data being copied. When `--upsert` CLI flag is active free_dbi pages are reused if possible. When, instead, default append mode data is stored, according to LMDB documentation, at the end of database.

A useful progress is provided like in this sample:
```
db_toolbox --datadir e:\tg\tg\chaindata copy --targetdir e:\tg\compact-temp --tables hAT hST

 Table                                         Progress
 ------------------------ --------------------------------------------------
 [FREE_DBI]               Skipped (SYSTEM TABLE)
 [MAIN_DBI]               Skipped (SYSTEM TABLE)
 ACS                      Skipped (no match --tables)
 B                        Skipped (no match --tables)
 CODE                     Skipped (no match --tables)
 CST2                     Skipped (no match --tables)
 DBINFO                   Skipped (no match --tables)
 DatabaseVersion          Skipped (no match --tables)
 H                        Skipped (unknown table)
 LastBlock                Skipped (no match --tables)
 LastFast                 Skipped (no match --tables)
 LastHeader               Skipped (no match --tables)
 PLAIN-ACS                Skipped (no match --tables)
 PLAIN-CST2               Skipped (no match --tables)
 PLAIN-SCS                Skipped (no match --tables)
 PLAIN-contractCode       Skipped (no match --tables)
 SCS                      Skipped (no match --tables)
 SNINFO                   Skipped (unknown table)
 SSP2                     Skipped (no match --tables)
 SSU2                     Skipped (no match --tables)
 TrieSync                 Skipped (no match --tables)
 b                        Skipped (no match --tables)
 call_from_index          Skipped (unknown table)
 call_to_index            Skipped (unknown table)
 clique-                  Skipped (no match --tables)
 contractCode             Skipped (no match --tables)
 ethereum-config-         Skipped (no match --tables)
 h                        Skipped (no match --tables)
 hAT                      ............................W.....................
 hST                      .W......W......W.......W......W.......W......W....
 iB                       Skipped (no match --tables)
 iTh2                     Skipped (no match --tables)
 incarnationMap           Skipped (no match --tables)
 l                        Skipped (no match --tables)
 log_address_index        Skipped (no match --tables)
 log_topic_index          Skipped (no match --tables)
 migrations               Skipped (no match --tables)
 r                        Skipped (no match --tables)
 secure-key-              Skipped (no match --tables)
 txSenders                Skipped (no match --tables)
 All done!
```

When a table is effectively being copied each dot `.` represent 2% of overall records.
An `W` instead of `.` means in the last 2% there has been a commit (according to `--commit` value)
