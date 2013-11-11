#!/usr/bin/env python
#
# git-p4s.py -- Import Perforce stream history into a git repository.
# Copyright 2013 Lukasz Mielicki <mielicki@gmail.com>
#
# https://github.com/lm1/git-p4s
#
# Meant for Perforce *stream* depot.
# Features merge detection and multiple streams import optimization.
# At this point only one way synchronization is supported.
#
# This tool is based on original git-p4 included in git distrubution however
# massive portions were rewritten (and many features dropped).
#
# git-p4.py -- A tool for bidirectional operation between a Perforce depot and git.
#
# Author: Simon Hausmann <simon@lst.de>
# Copyright: 2007 Simon Hausmann <simon@lst.de>
#            2007 Trolltech ASA
# License: MIT <http://www.opensource.org/licenses/mit-license.php>
#

_version = "0.301"

import sys
if sys.hexversion < 0x02060000:
    sys.stderr.write("git-p4s: requires Python 2.6 or later.\n")
    sys.exit(1)
import platform
import os
import optparse
import marshal
import subprocess
import tempfile
import time
import re
import shutil
import json
import string
import datetime
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore", category=DeprecationWarning)
    import sha

# Re-open standard streams with no buffering so prints get flushed immediately
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

_logLevel = 1

def log(msg):
    if _logLevel > 0:
        print(msg)

def verbose(msg):
    if _logLevel > 1:
        print(msg)

def debug(msg):
    if _logLevel > 2:
        print(msg)

def dump(obj):
    print(json.dumps(obj, indent=2))

def debugdump(obj):
    if _logLevel > 2:
        dump(obj)

def error(msg):
    sys.stderr.write("Error: " + msg + "\n")

def die(msg="Fatal error"):
    if _logLevel > 2:
        raise Exception(msg)
    else:
        error(msg)
        sys.exit(1)

def read_lines(filename):
    lines = []
    if os.path.exists(filename):
        with open(filename) as f:
            lines = [line.rstrip() for line in f]
    return lines

def append_lines(filename, lines):
    with open(filename, "a") as f:
        for line in lines:
            f.write(line + '\n')

def system(cmd):
    debug("Executing: %s" % str(cmd))
    return subprocess.call(cmd)

def read_pipe(c, ignore_error=False):
    debug("Reading pipe: %s" % str(c))
    expand = isinstance(c,basestring)
    stderr = None
    if ignore_error:
        stderr = open(os.devnull, "w")
    p = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=stderr, shell=expand)
    pipe = p.stdout
    val = pipe.read()
    pipe.close()
    ret = p.wait()
    if ignore_error:
        return (val, ret)
    if ret != 0:
        die("Command failed: %s" % str(c))
    return val

def read_pipe_lines(c):
    debug("Reading pipe: %s" % str(c))
    expand = isinstance(c, basestring)
    p = subprocess.Popen(c, stdout=subprocess.PIPE, shell=expand)
    pipe = p.stdout
    val = pipe.readlines()
    if pipe.close() or p.wait():
        die("Command failed: %s" % str(c))
    return val

def read_write_pipe_lines(cmd, input=[], ignore_error=False):
    debug("Reading pipe: %s" % str(cmd))
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate("\n".join(input))
    if not ignore_error and p.returncode != 0:
        die("Command failed: %s" % str(cmd))
    return (out.splitlines(), p.returncode)

def p4_build_cmd(cmd):
    """Build a suitable p4 command line.

    This consolidates building and returning a p4 command line into one
    location. It means that hooking into the environment, or other configuration
    can be done more easily.
    """
    real_cmd = ["p4"]

    user = gitConfig("git-p4.user")
    if len(user) > 0:
        real_cmd += ["-u",user]

    password = gitConfig("git-p4.password")
    if len(password) > 0:
        real_cmd += ["-P", password]

    port = gitConfig("git-p4.port")
    if len(port) > 0:
        real_cmd += ["-p", port]

    host = gitConfig("git-p4.host")
    if len(host) > 0:
        real_cmd += ["-H", host]

    client = gitConfig("git-p4.client")
    if len(client) > 0:
        real_cmd += ["-c", client]

    if isinstance(cmd,basestring):
        real_cmd = ' '.join(real_cmd) + ' ' + cmd
    else:
        real_cmd += cmd
    return real_cmd

def p4_read_pipe(c):
    real_cmd = p4_build_cmd(c)
    return read_pipe(real_cmd)

def p4_read_pipe_lines(c):
    """Specifically invoke p4 on the command supplied. """
    real_cmd = p4_build_cmd(c)
    return read_pipe_lines(real_cmd)

# Use generator instead of callback?
def p4CmdList(cmd, stdin=None, cb=None, ignore_error=False):

    if isinstance(cmd,basestring):
        cmd = "-G " + cmd
        expand = True
    else:
        cmd = ["-G"] + cmd
        expand = False

    cmd = p4_build_cmd(cmd)
    debug("Opening pipe: %s" % str(cmd))

    # Use a temporary file to avoid deadlock since P4 doesn't respond
    # until it reaches EOF on stdin
    stdin_file = None
    if stdin is not None:
        stdin_file = tempfile.TemporaryFile(prefix='p4-stdin', mode='w+b')
        if isinstance(stdin,basestring):
            stdin_file.write(stdin)
        else:
            for line in stdin:
                stdin_file.write(line + '\n')
        stdin_file.flush()
        stdin_file.seek(0)

    p4 = subprocess.Popen(cmd,
                          shell=expand,
                          stdin=stdin_file,
                          stdout=subprocess.PIPE)
    result = []
    try:
        while True:
            entry = marshal.load(p4.stdout)
            if not ignore_error and 'code' in entry and entry['code'] == 'error':
                verbose(entry)
                die("P4 error: %s" % entry['data'])
            if cb is not None:
                cb(entry)
            else:
                result.append(entry)
    except EOFError:
        pass
    # Call callback once more to signal end of data
    if cb is not None:
        cb(None)
    exitCode = p4.wait()
    if exitCode != 0 and not ignore_error:
        die("P4 error: %d" % exitCode);

    return result

def p4ChangesForPath(depotPath, begin=1, end=None):
    cmd = ["changes", "-s", "submitted", "-l",
           "%s/...@%d,%s" % (depotPath, begin, end if end else "#head")]
    return p4CmdList(cmd)

# Get labels from P4 using 'p4 labels' with optional arguments
# P4 labels may contain characters not allowed in git tags such as ':' and '^'
def p4CmdListLabels(args=[]):
    trans       = string.maketrans(r":/\[]", "-____")
    removeChars = "~^?"
    p4labels = p4CmdList(["labels"] + args)
    for l in p4labels:
        name = l["label"]
        l["name"] = name.translate(trans, removeChars)
    return p4labels

def P4StreamName(depotpath):
    return depotpath.split('/')[3]

def p4StreamPath(depotpath):
    return '/'.join(depotpath.split('/')[:4])

def p4RelPath(depotpath):
    return '/'.join(depotpath.split('/')[4:])

_p4_version_string = None
def p4_version_string():
    """Read the version string, showing just the last line, which
       hopefully is the interesting version bit.

       $ p4 -V
       Perforce - The Fast Software Configuration Management System.
       Copyright 1995-2011 Perforce Software.  All rights reserved.
       Rev. P4/NTX86/2011.1/393975 (2011/12/16).
    """
    global _p4_version_string
    if not _p4_version_string:
        a = p4_read_pipe_lines(["-V"])
        _p4_version_string = a[-1].rstrip()
    return _p4_version_string

# Return a tuple of the base type and modifiers. See "p4 help filetypes"
def split_p4_type(p4type):
    (base, _, mods) = p4type.partition("+")
    return (base, mods)

def calc_git_mode(p4type_touple):
    (type_base, type_mods) = p4type_touple
    git_mode = "100644"
    if "x" in type_mods:
        git_mode = "100755"
    if type_base == "symlink":
        git_mode = "120000"
    return git_mode

# Given a type base and modifier, return a regexp matching
# the keywords that can be expanded in the file
def p4_keywords_regexp_for_type(base, type_mods):
    if base in ("text", "unicode", "binary"):
        kwords = None
        if "ko" in type_mods:
            kwords = 'Id|Header'
        elif "k" in type_mods:
            kwords = 'Id|Header|Author|Date|DateTime|Change|File|Revision'
        else:
            return None
        pattern = r"""
            \$              # Starts with a dollar, followed by...
            (%s)            # one of the keywords, followed by...
            (:[^$\n]+)?     # possibly an old expansion, followed by...
            \$              # another dollar
            """ % kwords
        return pattern
    else:
        return None

# P4 wildcards are not allowed in filenames.  P4 complains
# if you simply add them, but you can force it with "-f", in
# which case it translates them into %xx encoding internally.
##def wildcard_decode(path):
##    # Search for and fix just these four characters.  Do % last so
##    # that fixing it does not inadvertently create new %-escapes.
##    # Cannot have * in a filename in windows; untested as to
##    # what p4 would do in such a case.
##    if not platform.system() == "Windows":
##        path = path.replace("%2A", "*")
##    path = path.replace("%23", "#") \
##               .replace("%40", "@") \
##               .replace("%25", "%")
##    return path

# Return the set of all git tags
def gitGetTags():
    gitTags = set()
    for line in read_pipe_lines(["git", "tag"]):
        tag = line.strip()
        gitTags.add(tag)
    return gitTags

def gitBranchExists(branch):
    proc = subprocess.Popen(["git", "rev-parse", branch],
                            stderr=subprocess.PIPE, stdout=subprocess.PIPE);
    proc.communicate()
    return proc.returncode == 0;

_gitConfig = {}

def gitConfig(key):
    if not _gitConfig.has_key(key):
        cmd = [ "git", "config", key ]
        s, _ = read_pipe(cmd, ignore_error=True)
        _gitConfig[key] = s.strip()
    return _gitConfig[key]

def gitConfigBool(key):
    """Return a bool, using git config --bool.  It is True only if the
       variable is set to true, and False if set to false or not present
       in the config."""
    if not _gitConfig.has_key(key):
        cmd = [ "git", "config", "--bool", key ]
        s, _ = read_pipe(cmd, ignore_error=True)
        v = s.strip()
        _gitConfig[key] = v == "true"
    return _gitConfig[key]

def gitConfigList(key):
    if not _gitConfig.has_key(key):
        s, _ = read_pipe(["git", "config", "--get-all", key], ignore_error=True)
        _gitConfig[key] = s.strip().split()
    return _gitConfig[key]

def gitVersion():
    version = read_pipe(["git", "--version"]).strip()
    return version

def gitIsBareRepo():
    bare = read_pipe(["git", "rev-parse", "--is-bare-repository"]).strip()
    return bare == "true"

def gitNotInRepo(branch, filelist):
    """Filter-out files already in a git repo"""
    # TODO cache batch-check result
    if not filelist:
        return []
    cmd = ["git", "cat-file", "--batch-check"]
    input = [branch + ":" + f for f in filelist]
    out, _ = read_write_pipe_lines(cmd, input)
    return set(f for f, status in zip(filelist, out)
                 if status.rpartition(" ")[2] == "missing")

def gitCheckIgnoreImpl(filelist):
    # TODO reimplement check-ignore logic to support P4 locations
    #      and bare repository (check-ignore doesn't work in bare repo)
    cmd = ["git", "check-ignore", "-v", "--stdin"]
    out, ret = read_write_pipe_lines(cmd, filelist, ignore_error=True)
    if ret == 0:
        ignored_files = [line.partition("\t")[2] for line in out]
    elif ret == 1:
        ignored_files = []
    else:
        die("Command failed: %s" % str(cmd))
    return ignored_files

def gitGetP4Streams():
    streams = {}
    cmd = ["git", "rev-parse", "--symbolic", "--remotes=p4"]
    for line in read_pipe_lines(cmd):
        branch = line.strip()
        if line.endswith("/HEAD"):
            continue
        data = extractMetaDataFromCommit(branch)
        if data:
            stream = data["stream"]
            assert(stream)
            data["stream"] = stream
            data["branch"] = branch
            data["change"] = int(data["change"])
            streams[stream] = data
    return streams

def gitSha1(contents):
    length = 0
    for d in contents:
        length += len(d)
    hash = sha.new()
    hash.update("blob %d\0" % length)
    for d in contents:
        hash.update(d)
    return hash.hexdigest();

# Parse commit header in format given by "git rev-list --header"
def extractMetaDatafromCommitHeader(header):
    data = {}
    lines = header.splitlines()
    assert(lines)
    assert(len(lines[0]) == 40)
    data["commit"] = lines[0]
    m = re.search (r"^ *\[p4s: (.*)\]$", lines[-1])
    if not m:
        return None
    for a in m.group(1).split(':'):
        vals = a.partition('=')
        (key, val) = (vals[0].strip(), vals[-1].strip())
        if val.endswith ('\"') and val.startswith('"'):
            val = val[1:-1]
        if key == "change":
            data[key] = int(val)
        else:
            data[key] = val
    return data

def extractMetaDataFromCommit(commit):
    cmd = "git rev-list -n 1 --header %s" % commit
    header = read_pipe(cmd)[:-1] # Chop trailing zero
    return extractMetaDatafromCommitHeader(header)

def sortByChange(dictList):
    temp = sorted([(int(d["change"]), d) for d in dictList])
    return [d for (_, d) in temp]

def branchFromStream(stream):
    assert(p4StreamPath(stream) ==  stream)
    return "refs/remotes/p4/" + stream.split('/')[3]

def banner():
    with open(sys.argv[0], "r") as file:
        blob = file.read()
    sha = gitSha1([blob])
    log("git-p4s version %s (%s)" % (_version, sha))
    if _logLevel > 2:
        debug("  " + platform.platform())
        debug("  Python " + sys.version)
        debug("  " + gitVersion())
        debug("  Perforce " + p4_version_string())

def timediff(time1):
    time2 = datetime.datetime.now()
    raw = time2 - time1
    seconds = raw.seconds + raw.microseconds / 500001
    return datetime.timedelta(raw.days, seconds)

class Command:
    def __init__(self):
        self.needsGit = True
        self.gitdir = ""
        self.verbose = False
        self.debug = False
        self.quiet = False
        self.usage = "[options]"
        self.options = [
            optparse.make_option(
                "--verbose", "-v", dest="verbose", action="store_true"),
            optparse.make_option(
                "--debug", "-d", dest="debug", action="store_true"),
            optparse.make_option(
                "--quiet", "-q", dest="quiet", action="store_true")
        ]

    def parse_args(self):
        if self.needsGit:
            self.options.append(optparse.make_option("--git-dir", dest="gitdir"))

        parser = optparse.OptionParser("Usage: %prog " + self.usage,
                                       self.options, description = self.description)
        (_, args) = parser.parse_args(sys.argv[2:], self);

        if self.needsGit:
            # Set GIT_DIR if --git-dir passed from command line
            if self.gitdir:
                os.environ["GIT_DIR"] = self.gitdir
            gitdir, ret = read_pipe("git rev-parse --git-dir", ignore_error=True)
            if ret != 0:
                die("Not a git repository!")
            self.gitdir = gitdir.strip()
            os.environ["GIT_DIR"] = self.gitdir

        global _logLevel
        if self.quiet:
            _logLevel = 0
        if self.verbose:
            _logLevel = 2
        if self.debug:
            _logLevel = 3

        banner()
        return args

    # This is required for the "append" optparse action
    def ensure_value(self, attr, value):
        if not hasattr(self, attr) or getattr(self, attr) is None:
            setattr(self, attr, value)
        return getattr(self, attr)

class P4UserMap:
    def __init__(self):
        self.userMapFromPerforceServer = False
        self.myP4UserId = None

    def p4UserId(self):
        if self.myP4UserId:
            return self.myP4UserId

        results = p4CmdList("user -o")
        for r in results:
            if r.has_key('User'):
                self.myP4UserId = r['User']
                return r['User']
        die("Could not find your p4 user id")

    def p4UserIsMe(self, p4User):
        # return True if the given p4 user is actually me
        me = self.p4UserId()
        if not p4User or p4User != me:
            return False
        else:
            return True

    def getUserCacheFilename(self):
        home = os.environ.get("HOME", os.environ.get("USERPROFILE"))
        return home + "/.gitp4-usercache.txt"

    def getUserMapFromPerforceServer(self):
        if self.userMapFromPerforceServer:
            return
        self.users = {}
        self.emails = {}

        for output in p4CmdList("users"):
            if not output.has_key("User"):
                continue
            self.users[output["User"]] = output["FullName"] + " <" + output["Email"] + ">"
            self.emails[output["Email"]] = output["User"]

        s = ""
        for (key, val) in self.users.items():
            s += "%s\t%s\n" % (key.expandtabs(1), val.expandtabs(1))

        open(self.getUserCacheFilename(), "wb").write(s)
        self.userMapFromPerforceServer = True

    def loadUserMapFromCache(self):
        self.users = {}
        self.userMapFromPerforceServer = False
        try:
            cache = open(self.getUserCacheFilename(), "rb")
            lines = cache.readlines()
            cache.close()
            for line in lines:
                entry = line.strip().split("\t")
                self.users[entry[0]] = entry[1]
        except IOError:
            self.getUserMapFromPerforceServer()

class P4Debug(Command):
    def __init__(self):
        Command.__init__(self)
        self.options = []
        self.description = "A tool to debug the output of p4 -G."
        self.needsGit = False

    def run(self):
        args = self.parse_args()
        dump(p4CmdList(args))
        return True

# Track mapping of changelist number to git commit in a cache file
# this helps with merge detection and labbels when --prune-empty is used
# and some changeslist are not in git repo
class CommitCache:
    # TODO read cache file on-demand only
    def __init__(self):
        self.marks = set()
        self.map = {}
        self.last_in_file = 0

    def readCacheFile(self, filename):
        debug("Reading commig cache")
        with open(filename) as file:
            for line in file:
                (cl, commit) = line.rstrip().split("\t")
                self.add(int(cl), commit)

    # TODO update by appending at the end
    def save(self, filename):
        with open(filename,"w") as f:
            for cl in sorted(self.map):
                f.write("%d\t%s\n" %(cl, self.map[cl]))

    def add(self, change, commit=None):
        ##debug("%7d -> %s" % (change, commit))
        if commit:
            if change in self.marks:
                self.marks.remove(change)
            assert(change not in self.map)
            self.map[change] = commit
        else:
            assert(change not in self.marks)
            assert(change not in self.map)
            self.marks.add(change)

    def get(self, change):
        if change in self.marks:
            return ":%d" % change
        elif change in self.map:
            return self.map[change]
        else:
            return None

    # TODO just read last entry if cache file not loaded yet
    def getMax(self):
        if self.map:
            return max(self.map.keys())
        else:
            return 0

    def readMarks(self, filename):
        if self.marks:
            debug("Reading marks")
            with open(filename) as file:
                for line in file:
                    (mark, commit) = line.rstrip().split()
                    self.add(int(mark[1:]), commit)
        assert(not self.marks)

    def addIgnored(self, ignored):
        assert(not self.marks)
        for (ign, chg) in ignored.iteritems():
            self.add(ign, self.get(chg))

    # Read git branch history till a first commit already in cache is found
    def readGitLog(self, stream):
        list = []
        branch = branchFromStream(stream)
        cmd = ["git", "rev-list", "--first-parent", "--header", branch]
        # This is simple and fast, but memory hungry
        # TODO read from stream by chunk
        for header in read_pipe(cmd).split('\0'):
            if not header:
                break
            data = extractMetaDatafromCommitHeader(header)
            if data:
                # stop after reaching parent branch
                if data["stream"] != stream:
                    break
                change = data["change"]
                list.append((change, data["commit"]))
                # If commit is already in cache during import it means that it is
                # already in other branch (i.e. branching point was reached)
                # but we still need it in the list since there may be some
                # missing changelists between this one and the next one
                if change in self.map:
                    break
            else:
                raise Exception("Not a git-p4s commit in git branch: " + commit)
        return list

    # Rebuild commit cache for given branch
    # Match P4 change log and git history and associate P4 change with git commit
    # even if some P4 changes are missing in git (imported with --prune-empty)
    # TODO follow p4 stream if reached parent stream
    def importHistoryFromGit(self, stream):
        gitlog = self.readGitLog(stream)
        ##debugdump(gitlog)
        head   = gitlog[0][0]  # last changelist
        origin = gitlog[-1][0] # first changelist or branching point
        if head in self.map:
            # head already in cache
            return
        changes = p4CmdList("changes -s submitted %s/...@%d,@%d"
                            % (stream, origin, head))
        changes = sorted([int(c["change"]) for c in changes])
        ##debugdump(changes)

        pi = iter(changes)
        gi = reversed(gitlog)
        (change, commit) = gi.next()
        for next in gi:
            ##print "git: %d %s" % (change, commit)
            more = True
            while more:
                cl = pi.next()
                if (cl >= next[0]):
                    (change, commit) = next
                    more = False
                ##print "%d: -> %d:%s" % (cl, change, commit)
                self.add(cl, commit)
        if change not in self.map:
            self.add(change, commit)

class P4Sync(Command, P4UserMap):

    def __init__(self):
        Command.__init__(self)
        P4UserMap.__init__(self)
        self.options = [
            optparse.make_option(
                "--map-labels", dest="mapLabels", action="append",
                metavar="PATTERN[=MAPPING]", help=(
                "Import labels matching a PATTERN using '*' as a wildcard.\n"
                "Multiple wildcards are supported. Optional MAPPING can be "
                "given to rename labels using $n (n is a digit) to substitue "
                "for n-th wildcard's match.\n"
                "E.g. --map-labels=* or --map-labels=rel*=v$1 "
                "{p4s.mapLabels}")),
            optparse.make_option(
                "--import-labels", dest="importLabels", action="store_true",
                help=("Import P4 labels matching imported depot path, "
                "static labels only. {p4s.importLabels}")),
            optparse.make_option(
                "--check-ignore", dest="checkIgnore", action="store_true",
                help="Skip files ignored by git, requires git 1.8.3+ "
                "{p4s.checkIgnore}"),
            optparse.make_option(
                "--prune-empty", dest="pruneEmpty", action="store_true",
                help="Skip commits with no files, only with --check-ignore. "
                "{p4s.pruneEmpty}"),
            optparse.make_option(
                "--no-merges", dest="importMerges", action="store_false",
                help="Do not import merges."),
            optparse.make_option(
                "--since",  dest="sinceChange", type="int",  action="store",
                metavar="FIRST", help=(
                "For new streams import starting from FIRST changelist")),
            optparse.make_option(
                "--limit", dest="limitChanges", type="int", action="store",
                metavar="LAST", help="Import up to LAST changelist")
        ] + self.options
        self.description = "Imports from Perforce into a git repository."
        self.usage += " [ //depot/stream ... ]"
        self.sinceChange = 1
        self.limitChanges = None # debug only
        self.importLabels = False
        self.mapLabels = []
        # TODO check for bare repo (check-ignore does not work with bare repo)
        self.checkIgnore = False
        self.pruneEmpty = False
        self.importMerges = True
        self.clientSpecDirs = None

        self.users = {}
        self.ignoredChanges = {}     # Changes ignored in this run

        # Mapping from P4 file digest to git hash
        # Used in single run to re-use blobs and conserve traffic
        # mostly for importing multiple streams
        self.blobmap = {}
        self.blobsReused = 0

    def importBegin(self):
        cmd = ["git", "fast-import", "--done"]
        cmd.append("--active-branches=%d" % len(self.streams))
        if self.marksFile:
            cmd.append("--export-marks=%s" % self.marksFile)
        debug("Running: %s" % str(cmd))
        self.importProcess = subprocess.Popen(cmd,
                  stdin=subprocess.PIPE,
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE);
        self.gitOutput = self.importProcess.stdout
        self.gitStream = self.importProcess.stdin
        self.gitError = self.importProcess.stderr

    def importDone(self):
        debug("fast-import done")
        self.gitStream.write("done\n")
        self.gitStream.close()
        if self.importProcess.wait() != 0:
            die("fast-import failed: %s" % self.gitError.read())
        self.gitOutput.close()
        self.gitError.close()
        os.unlink(self.marksFile)

    def checkpoint(self):
        """Force a checkpoint in fast-import and wait for it to finish"""
        debug("checkpoint")
        self.gitStream.write("checkpoint\n\n")
        self.gitStream.write("progress checkpoint\n\n")
        self.gitStream.flush()
        self.gitOutput.readline()

    # output one file from the P4 stream -- helper for streamP4Files
    def streamOneP4File(self, file, contents):
        depotFile = file["depotFile"]
        filerev   = "%s#%s" % (depotFile, file["rev0"])
        relPath = p4RelPath(depotFile)
        verbose(filerev)

        (type_base, type_mods) = split_p4_type(file["type0"])

        if type_base == "symlink":
            # p4 print on a symlink contains "target\n"; remove the newline
            data = ''.join(contents)
            contents = [data[:-1]]

        if type_base == "utf16":
            # p4 delivers different text in the python output to -G
            # than it does when using "print -o", or normal p4 client
            # operations.  utf16 is converted to ascii or utf8, perhaps.
            # But ascii text saved as -t utf16 is completely mangled.
            # Invoke print -o to get the real contents.
            #
            # On windows, the newlines will always be mangled by print, so put
            # them back too.  This is not needed to the cygwin windows version,
            # just the native "NT" type.
            #
            text = p4_read_pipe(["print", "-q", "-o", "-", filerev])
            if p4_version_string().find("/NT") >= 0:
                text = text.replace("\r\n", "\n")
            contents = [ text ]

        if type_base == "apple":
            # Apple filetype files will be streamed as a concatenation of
            # its appledouble header and the contents.  This is useless
            # on both macs and non-macs.  If using "print -q -o xx", it
            # will create "xx" with the data, and "%xx" with the header.
            # This is also not very useful.
            #
            # Ideally, someday, this script can learn how to generate
            # appledouble files directly and import those to git, but
            # non-mac machines can never find a use for apple filetype.
            log("Ignoring apple filetype file " + filerev)
            return

        # Note that we do not try to de-mangle keywords on utf16 files,
        # even though in theory somebody may want that.
        pattern = p4_keywords_regexp_for_type(type_base, type_mods)
        if pattern:
            regexp = re.compile(pattern, re.VERBOSE)
            text = "".join(contents)
            text = regexp.sub(r"$\1$", text)
            contents = [ text ]

        git_mode = calc_git_mode((type_base, type_mods))
        self.gitStream.write("M %s inline %s\n" % (git_mode, relPath))

        length = 0
        for d in contents:
            length += len(d)

        self.gitStream.write("data %d\n" % length)
        for d in contents:
            self.gitStream.write(d)
        self.gitStream.write("\n")

        if "digest0" in file:
            self.blobmap[file["digest0"]] = gitSha1(contents)

    def streamOneBlob(self, file, gitsha1):
        depotFile = file["depotFile"]
        relPath = p4RelPath(depotFile)
        verbose("%s#%s (cached)" % (depotFile, file["rev0"]))
        debug("  %s" % gitsha1)
        git_mode = calc_git_mode(split_p4_type(file["type0"]))
        self.gitStream.write("M %s %s %s\n" % (git_mode, gitsha1, relPath))
        self.blobsReused += 1

    def streamOneDeletion(self, file):
        depotFile = file["depotFile"]
        relPath = p4RelPath(depotFile)
        verbose("%s#%s (delete)" % (depotFile, file["rev0"]))
        self.gitStream.write("D %s\n" % relPath)

    # handle another chunk of streaming data
    def streamP4FilesCb(self, context, entry):
        curfile = context["curfile"]
        if not entry:
            # end of data -- stream the last file
            if curfile:
                self.streamOneP4File(curfile, context["data"])
            return

        code = entry.get("code", None)
        if code == "stat":
            assert("depotFile" in entry)
            if curfile:
                # output the current file first
                self.streamOneP4File(curfile, context["data"])
            # start a new file
            curfile = context["files"].next()
            context["curfile"] = curfile
            context["data"] = []
            # verify p4 print returned the same info
            assert(entry["depotFile"] == curfile["depotFile"])
            for x in ("rev", "time", "action", "type", "change"):
                assert(entry[x] == curfile[x + '0'])
        elif code in ("text", "binary") and "data" in entry:
            context["data"].append(entry["data"])
        else:
            debug(entry)
            err = "Unknown error."
            if code == "error":
                err = entry.get("data", err)
            if curfile:
                f = curfile["depotFile"]
                die("Error from p4 print for %s:\n %s" % (f, err))
            else:
                die("Error from p4 print: %s" % err)

    # Stream directly from "p4 files" into "git fast-import"
    def streamP4Files(self, files):
        DeleteActions = ( "delete", "move/delete", "purge" )
        filesToRead = []
        for f in files:
            if f["action0"] in DeleteActions:
                self.streamOneDeletion(f)
            elif f["digest0"] in self.blobmap:
                self.streamOneBlob(f, self.blobmap[f["digest0"]])
            else:
                filesToRead.append(f)
        # Limit number of files streamed at once to avoid "Too many open files" error
        # from p4 print command
        MaxFiles = 200
        while filesToRead:
            chunkOfFiles = filesToRead[:MaxFiles]
            filesToRead = filesToRead[MaxFiles:]

            context = {
                "files":    iter(chunkOfFiles),
                "curfile":  None,
                "data":     None
            }
            def streamP4FilesCb(entry):
                self.streamP4FilesCb(context, entry)

            fileArgs = ["%s#%s" % (f["depotFile"], f["rev0"]) for f in chunkOfFiles]

            p4CmdList(["-x", "-", "-b", str(len(fileArgs)), "print"],
                      stdin=fileArgs,
                      cb=streamP4FilesCb,
                      ignore_error=True)

    def make_email(self, userid):
        if userid in self.users:
            return self.users[userid]
        else:
            return "%s <a@b>" % userid

    def streamTag(self, tag, labelDetails, commit, epoch):
        debug("tag %s for commit %s" % (tag, commit))
        self.gitStream.write("tag %s\n" % tag)
        self.gitStream.write("from %s\n" % commit)

        description = "P4 label: %s\n" % labelDetails["label"]
        if labelDetails.get("Description", None):
            description += labelDetails["Description"].strip() + '\n'

        # Try to use the owner of the p4 label, or failing that,
        # the current p4 user id.
        owner = labelDetails.get("Owner", self.p4UserId())
        email = self.make_email(owner)
        # P4 doesn't know tagger TZ -- use UTC
        self.gitStream.write("tagger %s %s +0000\n" % (email, epoch))
        self.gitStream.write("data %d\n" % len(description))
        self.gitStream.write(description)
        self.gitStream.write("\n")

    def commit(self, stream, details, files, merge_from=[], integrates=[]):
        epoch  = details["time"]
        author = details["user"]
        branch = stream["branch"]
        debug("commit %s" % branch)

        change = int(details["change"])
        self.gitStream.write("commit %s\n" % branch)
        self.gitStream.write("mark :%d\n" % change)
        self.commitCache.add(change)

        if author not in self.users:
            self.getUserMapFromPerforceServer()
        # P4 doesn't know commiter TZ -- use UTC
        committer = "%s %s +0000" % (self.make_email(author), epoch)
        self.gitStream.write("committer %s\n" % committer)

        tag = "[p4s: stream = %s: change = %d" % (stream["stream"], change)
        if integrates:
            tag += ": integrates = " + ", ".join(integrates)
        tag += "]"
        self.gitStream.write("data <<EOT\n")
        self.gitStream.write(details["desc"].strip() + '\n')
        self.gitStream.write("\n%s\n\nEOT\n\n" % tag)

        tip = stream["commit"]
        if tip:
            debug("from %s" % tip)
            self.gitStream.write("from %s\n" % tip)
        stream["commit"] = "" # ":%d" % change
        stream["change"] = change

        for chg in merge_from:
            merge_point = self.commitCache.get(chg)
            debug("merge %d (%s)" % (chg, merge_point))
            self.gitStream.write("merge %s\n" % merge_point)

        self.streamP4Files(files)
        self.gitStream.write("\n")

    # Import p4 labels as git tags. A direct mapping does not
    # exist, so assume that if all the files are at the same revision
    # then we can use that, or it's something more complicated we should
    # just ignore.
    def importP4Labels(self):
        log("Importing labels...")
        # TODO use dict (name, revision) instead of keeping whole objects
        p4Labels = []
        ignoredP4Labels = read_lines(self.ignoredLabelsFile)

        if self.importLabels:
            # Get static labels for depot paths
            p4Labels.extend(p4CmdListLabels(["%s..." % p for p in self.streams.keys()]))
        if self.mapLabels:
            # Get labels matching each label pattern
            for (p4pattern, _) in self.labelMapping:
                args = []
                if p4pattern != '*':
                    args += ["-E", p4pattern]
                p4Labels.extend(p4CmdListLabels(args))

        # Remove duplicates
        allNames = set()
        for l in p4Labels[:]:
            if l["name"] in allNames:
                p4Labels.remove(l)
            else:
                allNames.add(l["name"])
        del allNames

        # Apply label mappings
        labels = []
        for (p4pattern, gitpattern) in self.labelMapping:
            wildcard = re.compile('^' + p4pattern.replace('*', "(.*)") + '$', re.IGNORECASE)
            target = gitpattern.replace('$' , '\\');
            if not target:
                continue
            for label in p4Labels[:]:
                p4name = label["name"]
                # Map to git name
                match = wildcard.match(p4name)
                if match:
                    p4Labels.remove(label)
                    label["gitname"] = match.expand(target);
                    labels.append(label)
        # Add remaining names w/o mapping
        for l in p4Labels:
            labels.append(l)

        if not labels:
            return

        gitTags = gitGetTags()

        missingP4Labels = [label for label in labels
                            if label.get("gitname", label["name"]) not in gitTags]

        ignore = []  # new labels to ignore
        for label in missingP4Labels:
            name = label["name"]
            if name in ignoredP4Labels:
                verbose("Ignoring label %s (failed to import previously)" % name)
                continue
            gitname = label.get("gitname", name)
            verbose("Importing label %s -> %s" % (name, gitname))

            change = None
            # Get revision '@number' for automatic labels
            if "Revision" in label:
                revstr = label["Revision"]
                if revstr.startswith('@'):
                    change = int(revstr[1:])
            else:
                # For a static label get the most recent change for each file in this label
                changes = p4CmdList(["changes", "-m", "1"] + ["%s/...@%s" % (p, name)
                                    for p in self.streams.keys()])
                if changes and "change" in changes[0]:
                    change = int(changes[0]["change"])

            if self.limitChanges and change > self.limitChanges:
                continue

            if not change:
                verbose("Label %s has no changelists - possibly deleted?" % name)
                ignore.append(name)
                continue
            commit = self.commitCache.get(change)
            if not commit:
                verbose("Could not find git commit for changelist %d" % change)
                ignore.append(name)
                continue
            # Use current time if there is no 'Update' field
            when = int(label.get("Update", time.time()))
            self.streamTag(gitname, label, commit, when)
            debug("p4 label %s mapped to git commit %s" % (name, commit))
        append_lines(self.ignoredLabelsFile, ignore)

    def getSrcFileRevsPerStream(_, stream, changelog):
        """Find source filerevs merged in given changelist"""
        streamFileRevListMap = {}
        for flog in changelog:
            i = 0
            while "how0,%d" % i in flog:
                how = flog["how0,%d" % i]
                if how.endswith(" from") or how == "ignored":
                    from_file   = flog["file0,%d" % i]
                    from_stream = p4StreamPath(from_file)
                    if from_stream != stream:
                        erev = int(flog["erev0,%d" % i][1:]) #TODO cleanup
                        list = streamFileRevListMap.setdefault(from_stream, [])
                        list.append("%s#%d" % (from_file, erev))
                i += 1
        return streamFileRevListMap

    def findSourceChange(_, sourceFileRevs):
        """Find max changelist for list of file revisions"""
        # use fstat to get the latest change among source fileRevs
        cmd = ["-x", "-", "-b", str(len(sourceFileRevs)),
               "fstat", "-L", "-r", "-Sd", "-m", "1", "-T", "headChange"]
        output = p4CmdList(cmd, sourceFileRevs)
        assert(len(output) == 1)
        return int(output[0]["headChange"])

    def isFileMerged(_, flog, targetFileRevs):
        file_merged = False
        i = 0
        while "how0,%d" % i in flog:
            how = flog["how0,%d" % i]
            if how.endswith(" into") or how == "ignored by":
                into_file   = flog["file0,%d" % i]
                if into_file not in targetFileRevs:
                    # File deleted/ignored
                    file_merged = True
                else:
                    erev = int(flog["erev0,%d" % i][1:])
                    if erev <= targetFileRevs[into_file]:
                        file_merged = True
                break # Only the last merge counts
            i += 1
        return file_merged

    def isFullyMerged(self, sourceFiles, targetFileRevMap):
        """Check whether all source files are merged into target file
        revisions"""
        unmerged = []
        for flog in sourceFiles:
            if not self.isFileMerged(flog, targetFileRevMap):
                unmerged.append(flog)
        if unmerged:
            log("Ignoring partial merge due to unmerged file(s)")
            max = 20
            for f in unmerged[:max]:
                verbose("  %s#%s" % (f["depotFile"], f["rev0"]))
            if len(unmerged) > max:
                verbose("  ...")
        else:
            return True

    def filelistFromP4Diff(_, diff):
        filelist = [p4RelPath(f["depotFile2"])
                    for f in diff if f["status"] != "left only"]
        filelist += [p4RelPath(f["depotFile"])
                     for f in diff if f["status"] == "left only"]
        return filelist

    def isMergeFrom(self, stream, change, srcStream, srcChange):
        """Check whether source change was fully merged to target stream"""
        cmd = ["diff2", "-q", "%s/...@%d" % (srcStream, srcChange),
                              "%s/...@%d" % (stream, change)]
        diff = p4CmdList(cmd, ignore_error=True)
        if diff[0]["code"] == "error":
            assert(diff[0]["generic"] == 17)
            return True   # No difference -- perfect merge or copy

        branch  = branchFromStream(stream)
        ignored = self.gitCheckIgnore(branch, self.filelistFromP4Diff(diff))

        sourceFileRevs = ["%s#%s" % (f["depotFile"], f["rev"])
                          for f in diff
                          if f["status"] != "right only"
                              and p4RelPath(f["depotFile"]) not in ignored]
        cmd = ["-x", "-", "-b", str(len(sourceFileRevs)), "filelog", "-m", "1"]
        sourceFiles = p4CmdList(cmd, sourceFileRevs)

        targetFileRevs = dict([(f["depotFile2"], int(f["rev2"]))
                               for f in diff
                               if f["status"] != "left only"
                                   and p4RelPath(f["depotFile2"]) not in ignored])

        return self.isFullyMerged(sourceFiles, targetFileRevs)

    def detectMerges(self, stream, change, changelog, integrates=[]):
        mergesFromChg = []
        srcFileRevsPerStream = self.getSrcFileRevsPerStream(stream, changelog)
        for (srcStream, srcFileRevs) in srcFileRevsPerStream.iteritems():
            srcChange = self.findSourceChange(srcFileRevs)
            verbose("Merge from %s@%d" % (srcStream, srcChange))
            integrates.append("%s@%d" % (srcStream, srcChange))
            if srcStream not in self.streams:
                verbose("Ignoring merge from unknown stream.")
                continue
            if not self.commitCache.get(srcChange):
                log("Ignoring merge from unknown changelist. "
                    "Merge from before initial import?")
                continue
            if self.isMergeFrom(stream, change, srcStream, srcChange):
                mergesFromChg.append(srcChange)
        return mergesFromChg

    def gitCheckIgnore(self, branch, filelist):
        """Check if files in the list are ignored by .gitignore or exclude
           Returns a set of ignored files"""
        if not self.checkIgnore or not filelist:
            return set()
        ignored_files = gitCheckIgnoreImpl(filelist)
        return gitNotInRepo(branch, ignored_files)

    def filterChangeFiles(self, stream, files):
        # TODO: perform client-spec mapping before filtering
        branch = stream["branch"]
        filenames = [p4RelPath(f["depotFile"]) for f in files]
        ignored_files = self.gitCheckIgnore(branch, filenames)
        filtered_files = []
        for f in files:
            if p4RelPath(f["depotFile"]) in ignored_files:
                log("%s#%s (ignored)" % (f["depotFile"], f["rev0"]))
            else:
                filtered_files.append(f)
        return filtered_files

    def importChange(self, stream, details):
        change = int(details["change"])
        depotpath = stream["stream"]

        if stream["change"]:
            # Use 'filelog -c' instead of 'describe' to get description and
            # information about files' orgin at the same time
            cmd = ["filelog", "-c", str(change), "-m", "1", "-s",
                   "%s/..." % depotpath]
        else:
            # First fetch -- all files at given revision
            cmd = ["filelog", "-m", "1", "-s",
                   "%s/...@%d" % (depotpath, change)]

        files = p4CmdList(cmd)
        files = self.filterChangeFiles(stream, files)

        merge_from = []
        integrates = []
        if self.importMerges:
            merges = self.detectMerges(depotpath, change, files, integrates)
            for m in merges:
                if m in self.ignoredChanges:
                    merge_from.append(self.ignoredChanges[m])
                else:
                    merge_from.append(m)
        try:
            if files or not self.pruneEmpty:
                self.commit(stream, details, files, merge_from, integrates)
            else:
                log("Ignoring empty changelist %d (-->%d)"
                    % (change, stream["change"]))
                self.ignoredChanges[change] = stream["change"]
        except IOError:
            die(self.gitError.read())

    def importChanges(self, changes):
        cnt = 0
        for details in sortByChange(changes):
            depotpath = p4StreamPath(details["path"])
            stream    = self.streams[depotpath]
            change    = int(details["change"])
            log("[%3d%%] Importing %s@%s"
                % (cnt * 100 / len(changes), depotpath, change))
            verbose("  " + details["desc"].lstrip().splitlines()[0])
            self.importChange(stream, details)
            cnt += 1

    def sanitizeLabelMapping(self):
        for (p4_name, git_name) in self.labelMapping:
            if not git_name:
                continue
            star_count = p4_name.count('*')
            substs = re.findall("\$.?", git_name)
            if not all([ord(g[1]) - ord('0') in range(1, star_count + 1) for g in substs]):
                die("Bad substitution '%s' --> '%s'" % (p4_name, git_name))
            if star_count > 0 and not substs:
                die("Mapping multiple P4 labels to a single git tag is not a good idea"
                    " ('%s' --> '%s')" % (p4_name, git_name))

    def streamsFromArgs(self, args):
        newstreams = {}
        for s in args:
            if s.endswith("/..."):
                s = s[:-4]
            if s.endswith("/"):
                s = s[:-1]
            if not s.startswith("//") or s != p4StreamPath(s):
                die("Invalid stream path: " + s)
            if s in self.streams:
                die("Stream already in git: " + s)
            newstreams[s] =  {
                "stream" : s,
                "branch" : branchFromStream(s),
                "change" : 0,
                "commit" : "",
                "new"    : True
            }
        return newstreams

    def getNewP4Changes(self):
        allChanges = []
        head = self.commitCache.getMax()
        for (path, stream) in self.streams.iteritems():
            log("Getting p4 changes for %s/..." % path)
            if "new" in stream:
                begin = self.sinceChange
            else:
                assert(head >= stream["change"])
                # Import from a firts change not in cache
                begin = head + 1
            changes = p4ChangesForPath(path, begin, end=self.limitChanges)
            allChanges.extend(changes)
        return allChanges

    def initCache(self):
        self.commitCache = CommitCache()
        if os.path.exists(self.cacheFile):
            self.commitCache.readCacheFile(self.cacheFile)
        else:
            # Re-build commit cache from existing streams
            for (path, stream) in self.streams.iteritems():
                if "new" in stream:
                    continue
                log("Re-building commit cache for %s..." % path)
                self.commitCache.importHistoryFromGit(path)

    def saveCache(self):
        self.commitCache.readMarks(self.marksFile)
        self.commitCache.addIgnored(self.ignoredChanges)
        self.commitCache.save(self.cacheFile)

    def createSymbolicRefs(self):
        for stream in self.streams.itervalues():
            if "new" not in stream or stream["change"] == 0:
                continue
            ref = "refs/heads/p4/%s" % P4StreamName(stream["stream"])
            if not gitBranchExists(ref):
                system(["git", "symbolic-ref", ref, stream["branch"]])

    def run(self):
        args = self.parse_args()
        time1 = datetime.datetime.now()
        debug(time1)
        self.cacheFile         = self.gitdir + "/p4s-commit-cache"
        self.marksFile         = self.gitdir + "/p4s-fast-import-marks.tmp"
        self.ignoredLabelsFile = self.gitdir + "/p4s-ignored-labels"

        if gitConfigBool("p4s.importLabels"):
            self.importLabels = True
        if gitConfigBool("p4s.checkIgnore"):
            self.checkIgnore = True
        if gitConfigBool("p4s.pruneEmpty"):
            self.pruneEmpty = True
        self.mapLabels.extend(gitConfigList("p4s.mapLabels"))
        self.labelMapping = []
        if self.mapLabels:
            self.labelMapping = [(p4, git) for (p4, _, git) in
                                (m.partition('=') for m in self.mapLabels)]
            self.sanitizeLabelMapping()
        if self.checkIgnore and gitIsBareRepo():
            die("--check-ignore does not work in bare repo.")

        self.streams = gitGetP4Streams()
        self.streams.update(self.streamsFromArgs(args))
        if not self.streams:
            die("No streams to sync.")
            return False
        debugdump(self.streams)


        self.initCache()
        self.loadUserMapFromCache()

        allChanges = self.getNewP4Changes()
        if not allChanges:
            log("Nothing to import.")

        self.importBegin()

        self.importChanges(allChanges)
        totalCommits = len(self.commitCache.marks)
        totalIgnored = len(self.ignoredChanges)

        # make fast-import checkpoint so marks file gets created
        self.checkpoint()
        self.saveCache()
        self.importP4Labels()

        self.importDone()
        self.createSymbolicRefs()

        verbose("Blob map size: %d, reused %d."
                % (len(self.blobmap), self.blobsReused))
        log("Imported %d changes (%d ignored) in %s"
            % (totalCommits, totalIgnored, timediff(time1)))
        return True

def printUsage(commands):
    print("Usage: git-p4s <command> [options]\n")
    print("Commands: %s\n" % ", ".join(commands))
    print("Try 'git-p4s <command> --help' for command specific help.\n")

def main():
    commands = {
        "debug" : P4Debug,
        "sync" : P4Sync,
    }

    if len(sys.argv) <= 1:
        printUsage(commands.keys())
        sys.exit(2)
    cmdName = sys.argv[1]
    try:
        cmd = commands[cmdName]()
    except KeyError:
        error("unknown command %s" % cmdName)
        log("")
        printUsage(commands.keys())
        sys.exit(2)

    if not cmd.run():
        sys.exit(2)

if __name__ == '__main__':
    main()
