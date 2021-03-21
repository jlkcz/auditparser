#!/usr/bin/env python3

import os
import re
import sys
import time
import argparse
from collections import Counter, defaultdict
from itertools import groupby
from operator import attrgetter

# non-stdlib dependencies
import dateparser


regex = re.compile(r'(?P<attr>\S+)=(("(?P<val1>[^"]+)")|(?P<val2>\S+))')


class LogLine:
    """Common class for all log lines"""

    defining_keys = ["apparmor", "operation", "msg"]

    def __init__(self, data):
        self.count = 0
        for k, v in data.items():
            setattr(self, k, v)
        self.time = parse_time(self.msg)

        # check if we have all the important data
        for key in self.defining_keys:
            if not hasattr(self, key):
                raise ValueError

    def __hash__(self):
        values = [getattr(self, key) for key in self.defining_keys]
        return hash(tuple(values))

    def __eq__(self, other):
        return all(
            [getattr(self, key) == getattr(other, key) for key in self.defining_keys]
        )


class FileLine(LogLine):
    """Represents apparmor errors related to files (permissions, manipulation)"""

    defining_keys = [
        "apparmor",
        "operation",
        "profile",
        "name",
        "requested_mask",
        "denied_mask",
    ]

    def __str__(self):
        return f"{self.profile}: {self.operation}({self.requested_mask}/{self.denied_mask}) {self.name} ({self.apparmor}|{self.time})"

    def fix(self):
        return f"{self.name} {self.requested_mask},"


class ExecLine(LogLine):
    """Represents apparmor errors related to execution of other files"""

    defining_keys = [
        "apparmor",
        "operation",
        "profile",
        "name",
        "comm",
        "requested_mask",
        "denied_mask",
    ]

    def __str__(self):
        return f"{self.profile} exec {self.name} with comm={self.comm} ({self.requested_mask}/{self.denied_mask}). ({self.apparmor}|{self.time})"

    def fix(self):
        return f"{self.name} Pix,"


class CapableLine(LogLine):
    """Represents apparmor errors about not-allowed capabilities"""

    defining_keys = ["profile", "capname"]

    def __str__(self):
        return (
            f"{self.profile}: capability {self.capname}. ({self.apparmor}|{self.time})"
        )

    def fix(self):
        return f"capability {self.capname},"


class SignalLine(LogLine):
    """Represents apparmor errors about not-allowed capabilities"""

    defining_keys = ["profile", "requested_mask", "denied_mask", "signal", "peer"]

    def __str__(self):
        return f"{self.profile}: signal ({self.requested_mask}/{self.denied_mask} {self.signal}) to {self.peer}. ({self.apparmor}|{self.time})"

    def fix(self):
        return f"signal ({self.requested_mask}) peer={self.peer},"


class ProfileLoadLine(LogLine):
    """Represents apparmor messages about profile replacement"""

    defining_keys = ["name"]

    @property
    def action(self):
        return self.operation.split("_")[1]

    def __str__(self):
        return f"{self.name} {self.action} at: {self.time}"

    def fix(self):
        return None


class ChangeProfileLine(LogLine):
    """Represents errors when proces is switching profiles"""

    defining_keys = ["info", "profile", "name"]

    def __str__(self):
        return f"{self.profile} switching to {self.name} failed: {self.info} at: {self.time}"

    def fix(self):
        return None


class UnknownLine:
    """Class for lines that make no sense to our parser"""

    def __init__(self, line):
        self.line = line

    def __str__(self):
        return f"Unrecognized line: {self.line}"


def parse_time(msg):
    match = re.search(r"audit\((?P<time>[0-9]+)\.", msg)
    if not match:
        raise ValueError
    return int(match.group("time"))


def parse_all(line):
    line = re.sub(r"[\x00-\x1F]+", " ", line)
    finds = [match.groupdict() for match in regex.finditer(line)]
    data = dict()
    for find in finds:
        data[find["attr"]] = find["val1"] or find["val2"]
    return data


def logline_factory(data):
    if data["operation"] == "capable":
        return CapableLine(data)
    elif data["operation"] == "exec":
        return ExecLine(data)
    elif data["operation"] in ["profile_replace", "profile_load", "profile_remove"]:
        return ProfileLoadLine(data)
    elif data["operation"] == "signal":
        return SignalLine(data)
    elif data["operation"] == "change_profile":
        return ChangeProfileLine(data)
    elif data["operation"] in [
        "file_inherit",
        "file_lock",
        "file_mmap",
        "file_perm",
        "mknod",
        "open",
        "rename_dest",
        "rename_src",
        "unlink",
        "chmod",
        "chown",
    ]:
        return FileLine(data)
    else:
        raise ValueError


def get_all_lines(filename, age, search_pattern=None):
    all_lines = []
    with open(filename, "r") as f:
        for line in f:
            if parse_time(line) < age:
                # check if msg is from last day if parse_time(line) < YESTERDAY:
                continue

            # parses matches into a dict
            data = parse_all(line)

            # not AVC, not interesting
            if data["type"] != "AVC":
                continue

            # only find
            if search_pattern and not re.search(search_pattern, data["profile"]):
                continue

            try:
                line_obj = logline_factory(data)
            except ValueError:
                line_obj = UnknownLine(line)
            all_lines.append(line_obj)
    return all_lines

def sort_lines(lines):
    """ sort lines into separate groups"""
    known_lines = [line for line in all_lines if not isinstance(line, UnknownLine)]
    unknown_lines = [line for line in all_lines if isinstance(line, UnknownLine)]
    return {"known": known_lines, "unknown": unknown_lines}


def deduplicate_lines(lines):
    """ Deduplicates lines and adds counts"""
    counter = Counter(map(hash, lines))
    unique_list = list(set(lines))
    for line in unique_list:
        line.count = counter[hash(line)]
    return list(unique_list)

def group_lines(lines):
    grouped_lines = defaultdict(list)
    for line in lines:
        grouped_lines[line.profile].append(line)
    return grouped_lines


############## Here lies __main__ behaviour ###################################

parser = argparse.ArgumentParser(
    prog="auditparser",
    usage="%(prog)s [options]",
    description="Gets AppArmor log data from auditd logs",
)
parser.add_argument(
    "-t",
    "--since",
    type=lambda s: dateparser.parse(s),
    default="1d",
    help="Human readable date (like 1d, 1h) since when to display logs (default: 1d)",
)
parser.add_argument(
    "-p", "--profile", type=str, help="show only lines for this profile (can be regex)"
)
parser.add_argument(
    "-u", "--unknown-only", action="store_true", help="show only unknown lines"
)
parser.add_argument(
    "-f",
    "--fix",
    action="store_true",
    help="show suggested fixes instead of error lines",
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "-l",
    "--logfile",
    type=str,
    default="/var/log/audit/audit.log",
    help="location of the audit.log file. (default: /var/log/audit/audit.log)",
)
group.add_argument(
    "-s",
    "--stdin",
    action="store_true",
    help="read log data from stdin instead of file",
)
parser.add_argument(
    "-m", "--manual", action="store_true", help="show abridged AppArmor profiles manual"
)

AA_MANUAL = """These are basic hints for AppArmor profile.

r - read
w - write
a - append (implied by w)
x - execute
m - memory map executable
k - lock (requires r or w, AppArmor 2.1 and later)
l - link
Ix - the new process should run under the current profile
Cx - the new process should run under a child profile that matches the name of the executable
Px - the new process should run under another profile that matches the name of the executable
Ux - the new process should run unconfined

More info at: https://gitlab.com/apparmor/apparmor/-/wikis/QuickProfileLanguage"""


if __name__ == "__main__":
    # manage arguments
    args = parser.parse_args()
    if args.manual:
        print(AA_MANUAL)
        sys.exit(0)

    log_age = args.since.timestamp()
    log_file = "/dev/stdin" if args.stdin else args.logfile
    if not args.stdin:
        if not os.path.isfile(log_file):
            print(f"No such logfile: {log_file}")
            sys.exit(1)

    # parse and sort all lines
    all_lines = get_all_lines(log_file, log_age, args.profile)
    categorized_lines = sort_lines(all_lines)

    if args.fix:
        print("\033[91m*****************************************************************************")
        print("** WARNING! These are only suggestions. Admins discretion needed! WARNING! **")
        print("*****************************************************************************\033[0m")

    # known lines are processed only if there is no -u switch
    if not args.unknown_only:
        deduped_lines = deduplicate_lines(categorized_lines["known"])
        groups = group_lines(deduped_lines)

        # lets print known issues profile by profile
        for name in sorted(groups.keys()):
            print(f"===== profile {name} ======")
            for line in groups[name]:
                if args.fix:
                    print(line.fix())
                else:
                    line_str = str(line)
                    print(f"{line.count}x: {line_str}")

    # if there are any unknown lines, print them
    unknown_lines = set(categorized_lines["unknown"])
    if unknown_lines:
        print(f"===== Unknown/unparseable lines ======")
        for line in unknown_lines:
            print(line)

