git-p4s
=======

Import Perforce stream history into a git repository.

## Usage
Make sure P4PORT variable is set and perform the following command inside a fresh git repo:

    git-p4s.py sync //depot/mystream1 //depot/mystream2

To fetch latest changes:

    git-p4s.py sync

### What is git-p4s?
git-p4s is a fork of the original git-p4 utility bundled with git. 
It is meant for P4 stream depot. Major features are:
- Supports multiple P4 streams in a single git repository
- Incremental update
- Merge detection
- History filtering on file level
- Optimized import of multiple streams
- Import of automatic and static labels

### Requirements/limitations
git-p4s works only with streamed depot (requires 2012 Perforce client or newer). Only one-way import is supported.

### Merge detection
Following git philosophy only complete merges are imported. Partial merges are imported as regular single parented commits however integrations are recorded in a commit message. Merges with multiple parents are supported.
Note that merge can be only imported if the merge origin is already imported. To ensure this is the case all streams must be imported together.

### Filtering
History can be filtered during import with `--check-ignore` option (leveraging `.gitignore` or `.git/info/exclude`). This is used to exclude large binaries or build outputs. Use with care. `--prune-empty` will skip commits which become empty after filtering.

### Performance
git-p4s caches blobs digests during run therefore it is recommended to import all desired streams at once to increase blob re-use. As its predecessor git-p4s uses `p4 print` command to retrieve file contents.

### Repository size
Since git-p4s internally uses *git fast-import* a resulting pack file may not be optimally compressed, use `git gc --aggressive` to repack the repository after initial import. For some project history filtering may be helpful.

### Line endings
git-p4s retrieves raw data from Perforce server and uses *git fast-import* to load blobs into a git repository. None of these operations performs line ending conversion. Since P4 server seems to use Unix newlines internally therefore on Windows `core.autocrlf = true` is a recommended setting for projects using Windows line ending (CRLF).

### Is git-p4s compatible with the original git-p4?
No.

### Why fork?
Original git-p4 utility does not support P4 streams well. Streamed depot constraints let implementation take important assumptions while maintaining backward compatibility with git-p4 and support for non-streamed depots would makes it much harder to reliably implement merge detection.
