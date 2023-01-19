# Author of orignial script: jlevy
# Created: 2014-07-09
# https://github.com/jlevy/repren

import re
import sys
import os
import shutil
import bisect

from builtins import zip
from builtins import object


# Definitive version. Update with each release.
VERSION = "0.3.10"

DESCRIPTION = "repren: Multi-pattern string replacement and file renaming"

BACKUP_SUFFIX = b".orig"
TEMP_SUFFIX = b".repren.tmp"
DEFAULT_EXCLUDE_PAT = b"\."


def log(op, msg):
    if op:
        msg = "- %s: %s" % (op, msg)
    print(msg, file=sys.stderr)


def fail(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


class _Tally(object):
    def __init__(self):
        self.files = 0
        self.chars = 0
        self.matches = 0
        self.valid_matches = 0
        self.files_changed = 0
        self.files_rewritten = 0
        self.renames = 0


_tally = _Tally()

# --- String matching ---


def _overlap(match1, match2):
    return match1.start() < match2.end() and match2.start() < match1.end()


def _sort_drop_overlaps(matches, source_name=None):
    '''Select and sort a set of disjoint intervals, omitting ones that overlap.'''
    non_overlaps = []
    starts = []
    for (match, replacement) in matches:
        index = bisect.bisect_left(starts, match.start())
        if index > 0:
            (prev_match, _) = non_overlaps[index - 1]
            if _overlap(prev_match, match):
                log(source_name, "Skipping overlapping match '%s' of '%s' that overlaps '%s' of '%s' on its left" %
                    (match.group(), match.re.pattern, prev_match.group(), prev_match.re.pattern))
                continue
        if index < len(non_overlaps):
            (next_match, _) = non_overlaps[index]
            if _overlap(next_match, match):
                log(source_name, "Skipping overlapping match '%s' of '%s' that overlaps '%s' of '%s' on its right" %
                    (match.group(), match.re.pattern, next_match.group(), next_match.re.pattern))
                continue
        starts.insert(index, match.start())
        non_overlaps.insert(index, (match, replacement))
    return non_overlaps


def _apply_replacements(input_str, matches):
    out = []
    pos = 0
    for (match, replacement) in matches:
        out.append(input_str[pos:match.start()])
        out.append(match.expand(replacement))
        pos = match.end()
    out.append(input_str[pos:])
    return b"".join(out)


class _MatchCounts(object):
    def __init__(self, found=0, valid=0):
        self.found = found
        self.valid = valid

    def add(self, o):
        self.found += o.found
        self.valid += o.valid


def multi_replace(input_str, patterns, is_path=False, source_name=None):
    '''Replace all occurrences in the input given a list of patterns (regex,
  replacement), simultaneously, so that no replacement affects any other. E.g.
  { xxx -> yyy, yyy -> xxx } or { xxx -> yyy, y -> z } are possible. If matches
  overlap, one is selected, with matches appearing earlier in the list of
  patterns preferred.
  '''
    matches = []
    for (regex, replacement) in patterns:
        for match in regex.finditer(input_str):
            matches.append((match, replacement))
    valid_matches = _sort_drop_overlaps(matches, source_name=source_name)
    result = _apply_replacements(input_str, valid_matches)

    global _tally
    if not is_path:
        _tally.chars += len(input_str)
        _tally.matches += len(matches)
        _tally.valid_matches += len(valid_matches)

    return result, _MatchCounts(len(matches), len(valid_matches))

# --- Case handling (only used for case-preserving magic) ---

# TODO: Could handle dash-separated names as well.

# FooBarBaz -> Foo, Bar, Baz
# XMLFooHTTPBar -> XML, Foo, HTTP, Bar
_camel_split_pat1 = re.compile(b"([^A-Z])([A-Z])")
_camel_split_pat2 = re.compile(b"([A-Z])([A-Z][^A-Z])")

_name_pat = re.compile(b"\w+")


def _split_name(name):
    '''Split a camel-case or underscore-formatted name into words. Return separator and words.'''
    if name.find(b"_") >= 0:
        return b"_", name.split(b"_")
    else:
        temp = _camel_split_pat1.sub(b"\\1\t\\2", name)
        temp = _camel_split_pat2.sub(b"\\1\t\\2", temp)
        return b"", temp.split(b"\t")


def _capitalize(word):
    word = word.decode()
    return (word[0].upper() + word[1:].lower()).encode()


def to_lower_camel(name):
    words = _split_name(name)[1]
    return words[0].decode().lower().encode() + b"".join([_capitalize(word) for word in words[1:]])


def to_upper_camel(name):
    words = _split_name(name)[1]
    return b"".join([_capitalize(word) for word in words])


def to_lower_underscore(name):
    words = _split_name(name)[1]
    return b"_".join([word.lower() for word in words])


def to_upper_underscore(name):
    words = _split_name(name)[1]
    return b"_".join([word.upper() for word in words])


def _transform_expr(expr, transform):
    return _name_pat.sub(lambda m: transform(m.group()), expr)


def all_case_variants(expr):
    '''Return all casing variations of an expression, replacing each name with
  lower- and upper-case camel-case and underscore style names, in fixed order.'''
    return [_transform_expr(expr, transform)
            for transform in [to_lower_camel, to_upper_camel, to_lower_underscore, to_upper_underscore]]

# --- File handling ---


def make_parent_dirs(path):
    '''Ensure parent directories of a file are created as needed.'''
    dirname = os.path.dirname(path)
    if dirname and not os.path.isdir(dirname):
        os.makedirs(dirname)
    return path


def move_file(source_path, dest_path, clobber=False):
    if not clobber:
        trailing_num = re.compile("(.*)[.]\d+$")
        i = 1
        while os.path.exists(dest_path):
            match = trailing_num.match(dest_path)
            if match:
                dest_path = match.group(1)
            dest_path = "%s.%s" % (dest_path, i)
            i += 1
    shutil.move(source_path, dest_path)


def transform_stream(transform, stream_in, stream_out, by_line=False):
    counts = _MatchCounts()
    if by_line:
        for line in stream_in:
            if transform:
                (new_line, new_counts) = transform(line)
                counts.add(new_counts)
            else:
                new_line = line
            stream_out.write(new_line)
    else:
        contents = stream_in.read()
        (new_contents, new_counts) = transform(contents) if transform else contents
        stream_out.write(new_contents)
    return counts


def transform_file(transform, source_path, dest_path,
                   orig_suffix=BACKUP_SUFFIX,
                   temp_suffix=TEMP_SUFFIX,
                   by_line=False,
                   dry_run=False, clean=False):
    '''Transform full contents of file at source_path with specified function,
  either line-by-line or at once in memory, writing dest_path atomically and keeping a backup.
  Source and destination may be the same path.'''
    counts = _MatchCounts()
    global _tally
    changed = False
    if transform:
        orig_path = source_path + orig_suffix
        temp_path = dest_path + temp_suffix
        # TODO: This will create a directory even in dry_run mode, but perhaps that's acceptable.
        # https://github.com/jlevy/repren/issues/6
        make_parent_dirs(temp_path)
        perms = os.stat(source_path).st_mode & 0o777
        with open(source_path, "rb") as stream_in:
            with os.fdopen(os.open(temp_path, os.O_WRONLY | os.O_CREAT, perms), "wb") as stream_out:
                counts = transform_stream(transform, stream_in, stream_out, by_line=by_line)

        # All the above happens in dry-run mode so we get tallies.
        # Important: We don't modify original file until the above succeeds without exceptions.
        if not dry_run and (dest_path != source_path or counts.found > 0):
            move_file(source_path, orig_path, clobber=True)
            move_file(temp_path, dest_path, clobber=False)
            if clean:
                os.remove(orig_path)
        else:
            # If we're in dry-run mode, or if there were no changes at all, just forget the output.
            os.remove(temp_path)

        _tally.files += 1
        if counts.found > 0:
            _tally.files_rewritten += 1
            changed = True
        if dest_path != source_path:
            _tally.renames += 1
            changed = True
    elif dest_path != source_path:
        if not dry_run:
            make_parent_dirs(dest_path)
            move_file(source_path, dest_path, clobber=False)
        _tally.files += 1
        _tally.renames += 1
        changed = True
    if changed:
        _tally.files_changed += 1

    return counts


def rewrite_file(path, patterns, do_renames=False, do_contents=False, by_line=False, dry_run=False, clean=False):
    dest_path = multi_replace(path, patterns, is_path=True)[0] if do_renames else path
    transform = None
    if do_contents:
        transform = lambda contents: multi_replace(contents, patterns, source_name=path)
    counts = transform_file(transform, path, dest_path, by_line=by_line, dry_run=dry_run, clean=clean)
    if counts.found > 0:
        log("modify", "%s: %s matches" % (path.decode(), counts.found))
    if dest_path != path:
        log("rename", "%s -> %s" % (path.decode(), dest_path.decode()))


def walk_files(paths, exclude_pat=DEFAULT_EXCLUDE_PAT):
    out = []
    exclude_re = re.compile(exclude_pat)
    for path in paths:
        if not os.path.exists(path):
            fail("path not found: %s" % path)
        if os.path.isfile(path):
            out.append(path)
        else:
            for (root, dirs, files) in os.walk(path):
                # Prune files that are excluded, and always prune backup files.
                out += [os.path.join(root, f) for f in files
                        if not exclude_re.match(f) and not f.endswith(BACKUP_SUFFIX) and not f.endswith(TEMP_SUFFIX)]
                # Prune subdirectories.
                dirs[:] = [d for d in dirs if not exclude_re.match(d)]
    return out


def rewrite_files(root_paths, patterns,
                  do_renames=False,
                  do_contents=False,
                  exclude_pat=DEFAULT_EXCLUDE_PAT,
                  by_line=False,
                  dry_run=False,
                  clean=False):
    paths = walk_files(root_paths, exclude_pat=exclude_pat)
    log(None, "Found %s files in: %s" % (len(paths), ", ".join([path.decode() for path in root_paths])))
    for path in paths:
        rewrite_file(path, patterns, do_renames=do_renames, do_contents=do_contents, by_line=by_line, dry_run=dry_run, clean=clean)

# --- Invocation ---


def parse_patterns(patterns_str, literal=False, word_breaks=False, insensitive=False, dotall=False, preserve_case=False):
    patterns = []
    flags = (re.IGNORECASE if insensitive else 0) | (re.DOTALL if dotall else 0)
    for line in patterns_str.splitlines():
        bits = None
        try:
            bits = line.split(b'\t')
            if line.strip().startswith(b"#"):
                continue
            elif line.strip() and len(bits) == 2:
                (regex, replacement) = bits
                if literal:
                    regex = re.escape(regex)
                pairs = []
                if preserve_case:
                    pairs += list(zip(all_case_variants(regex), all_case_variants(replacement)))
                pairs.append((regex, replacement))
                # Avoid spurious overlap warnings by removing dups.
                pairs = sorted(set(pairs))
                for (regex_variant, replacement_variant) in pairs:
                    if word_breaks:
                        regex_variant = (r'\b' + regex_variant.decode() + r'\b').encode()
                    patterns.append((re.compile(regex_variant, flags), replacement_variant))
            else:
                fail("invalid line in pattern file: %s" % bits)
        except Exception as e:
            fail("error parsing pattern: %s: %s" % (e, bits))
    return patterns


if __name__ == '__main__':
    try:
        new_name = sys.argv[1]
    except IndexError:
        print('You must define new name')
        exit(1)
    pat_str = b'%s\t%s' % ('netbox_newplugin'.encode(), new_name.encode())
    patterns = parse_patterns(pat_str)
    root_paths = ['.'.encode()]
    rewrite_files(
        root_paths, patterns,
        do_renames=True,
        do_contents=True,
        exclude_pat=b"repren.py",
        by_line=True,
        dry_run=False,
        clean=True
    )
    pat_str = b'%s\t%s' % ('Newplugin'.encode(), new_name.replace('_', '').capitalize().encode())
    patterns = parse_patterns(pat_str)
    rewrite_files(
        root_paths, patterns,
        do_renames=True,
        do_contents=True,
        exclude_pat=b"repren.py",
        by_line=True,
        dry_run=False,
        clean=True)
    try:
        shutil.rmtree('./netbox_newplugin/')
    except Exception:
        pass
    try:
        os.remove('README.md')
    except Exception:
        pass
    try:
        os.rename('README.me', 'README.md')
    except Exception:
        pass
