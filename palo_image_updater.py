"""Net_Dev_CLI: check and update PAN-OS and dynamic content on Palo Alto firewalls over the XML API.

Usage:  poetry run python palo_image_updater.py

Credentials and API keys are held in memory for this run only and never written to disk.
"""
import contextlib
import getpass
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import xml.etree.ElementTree as ET
import datetime
from pathlib import Path
from xml.sax.saxutils import escape

import requests
import urllib3
import yaml

# Built into an EXE by PyInstaller (build_exe.ps1): config.yml lives in a config folder next to
# the EXE, and the skeleton is unpacked with the bundled code into sys._MEIPASS
FROZEN = getattr(sys, 'frozen', False)
BASE_DIR = Path(sys.executable if FROZEN else __file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, '_MEIPASS', BASE_DIR))
CONFIG_PATH = BASE_DIR / 'config' / 'config.yml'
SKELETON_PATH = BUNDLE_DIR / 'config' / 'skeleton_config.yml'
# verify_ssl false: each firewall's certificate, trusted the first time it connects (check_certificates)
CERTS_PATH = BASE_DIR / 'config' / 'known_certs.txt'

APP_TITLE = 'Net_Dev_CLI'
REPO_URL = 'https://github.com/wmfreeman/Net_Dev_CLI'
GIT_TIMEOUT = 60
# A change to either means the dependencies need reinstalling after an update
DEPENDENCY_FILES = ('pyproject.toml', 'poetry.lock')
CONNECT_TIMEOUT = 10
DEFAULT_PORT = 443

# Connect via SSH (Palo Firewall Management option 8) uses Windows' built-in OpenSSH client
SSH_CLIENT = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'OpenSSH' / 'ssh.exe'
SSH_VERSION = re.compile(r'OpenSSH\w*?_(\d+)\.(\d+)')
# Filling in the password needs OpenSSH 8.5: SSH_ASKPASS_REQUIRE (8.4) lets ssh take it from this
# tool, and 8.5 starts every keyboard-interactive prompt with '(user@host)', so a prompt a JumpHost
# sends can't pass for the firewall's (prompt_names)
SSH_ASKPASS_VERSION = (8, 5)
# Set only in ssh's environment: tells this tool, started again by ssh to answer a prompt, where to
# fetch the password (AskpassServer)
ASKPASS_ENV = 'NET_DEV_CLI_ASKPASS'
# ssh prompts: a password (filled in once) and a yes/no question (the host key; typed, with echo)
SSH_PASSWORD_PROMPT = re.compile(r'password', re.IGNORECASE)
SSH_CONFIRM_PROMPT = re.compile(r'\(yes/no', re.IGNORECASE)

# Target input. Checked in this order, because a file path can contain spaces or commas.
# A path has a folder separator, a drive letter or a list-file extension
FILE_PATTERN = re.compile(r'[\\/]|^[A-Za-z]:|\.(?:txt|csv|lst|list)$', re.IGNORECASE)
# Anything with a comma, semicolon or space in it is a list
LIST_SEPARATORS = re.compile(r'[,;\s]+')
# One entry: host, optionally followed by :port
ENTRY_PATTERN = re.compile(r'^(?P<name>[^:\s]+)(?::(?P<port>\d{1,5}))?$')
# Only digits and dots - has to be a valid IPv4 address, never a DNS name
IPV4_PATTERN = re.compile(r'^[\d.]+$')
# RFC 1123 hostname: dot-separated labels of letters, digits and inner hyphens
HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)
# One part of a selection: a number, or a range like 2-4
SELECTION_PATTERN = re.compile(r'^\s*(\d+)\s*(?:-\s*(\d+)\s*)?$')
# Target prompt: the default when devices are known (all of them), and a View Devices number
KNOWN_TARGET = 'known'
INDEX_PATTERN = re.compile(r'^\d+$')
# First-column values that mark a header row in a target file (e.g. a NetBox CSV export)
HEADER_WORDS = {'host', 'hostname', 'name', 'device', 'fqdn', 'ip', 'address', 'target', 'firewall'}

# <show><system><info> fields -> column headings
SYSTEM_FIELDS = {
    'hostname': 'Hostname',
    'model': 'Model',
}
# Content column heading -> (version field, release date field). URL Filtering's version is already a date.
VERSION_FIELDS = {
    'Apps & Threats': ('app-version', 'app-release-date'),
    'Antivirus': ('av-version', 'av-release-date'),
    'WildFire': ('wildfire-version', 'wildfire-release-date'),
    'URL Filtering': ('url-filtering-version', None),
    'Device-ID': ('device-dictionary-version', 'device-dictionary-release-date'),
    'GP Client': ('global-protect-client-package-version', None),
    'GP Clientless': ('global-protect-clientless-vpn-version', 'global-protect-clientless-vpn-release-date'),
    'GP Data File': ('global-protect-datafile-version', 'global-protect-datafile-release-date'),
}
# What the firewall reports for a component that isn't installed or licensed
NOT_INSTALLED = ('', '0')
# '2026/10/28 15:43:39 PDT' -> 2026-10-28
DATE_PATTERN = re.compile(r'(\d{4})[/-](\d{2})[/-](\d{2})')

# Updatable content: menu label -> (<request> path, show system info version field).
# 'check' fetches the release list from Palo Alto; 'info' returns the firewall's cached copy.
CONTENT_TYPES = {
    'Apps & Threats': (('content', 'upgrade'), 'app-version'),
    'Antivirus': (('anti-virus', 'upgrade'), 'av-version'),
    'WildFire': (('wildfire', 'upgrade'), 'wildfire-version'),
    'GP Client': (('global-protect-client', 'software'), 'global-protect-client-package-version'),
}
# Install flag for Apps & Threats, as shown by the firewall's API browser (it takes no value)
DISABLE_NEW_APPS = '<disable-new-content></disable-new-content>'
PANOS = 'PAN-OS'
PANOS_REQUEST = ('system', 'software')
# Delete commands, as shown by a firewall's API browser (https://<firewall>/api > Operational
# Commands > delete). {version} and {filename} are filled in from the release list.
DELETE_COMMANDS = {
    'content-cache': '<delete><content><cache><old-content></old-content></cache></content></delete>',
    PANOS: '<delete><software><version>{version}</version></software></delete>',
    'Apps & Threats': '<delete><content><update>{filename}</update></content></delete>',
}

PASS, FAIL, SKIPPED, EXPIRED = 'PASS', 'FAIL', 'SKIPPED', 'EXPIRED'
# Errors that mean the firewall has ended the session behind an API key, e.g.
# 'Credential Expired: LUFR...YUE9 has expired.' after the admin idle timeout
SESSION_ENDED = re.compile(r'credential expired|has expired|session timed out', re.IGNORECASE)
# Read-only call the keep-alive sends to firewalls that have been idle (the same call that
# confirms each key at authentication)
KEEPALIVE_CMD = '<show><system><info></info></system></show>'
# Default keepalive_interval, how often the keep-alive worker looks for idle firewalls, and how
# many pings it sends at once
KEEPALIVE_INTERVAL = 60
KEEPALIVE_WAKE = 10
KEEPALIVE_PARALLEL = 16
# Default app_idle_timeout: minutes with no activity before the tool disconnects
APP_IDLE_TIMEOUT = 30
DONE, FAILED, STOPPED = 'DONE', 'FAILED', 'STOPPED'
# A firewall a batch stopped before starting (stop_after_failures, or not continuing after a test
# group), and a request that got no reply, so whether it started is unknown
NOT_STARTED, UNKNOWN = 'NOT STARTED', 'UNKNOWN'
# Download and install jobs: default seconds between status polls (job_poll_interval in
# config.yml), and polls in a row that can fail (the management plane can be busy
# mid-install) before the job is reported as lost
JOB_POLL_INTERVAL = 10
JOB_POLL_FAILURES = 3

# Running jobs: nothing that changes a firewall (delete, download, install, cache clear)
# starts while it has a job queued or running - started from this tool, the web UI or Panorama
JOBS_ALL_CMD = '<show><jobs><all></all></jobs></show>'
JOB_BUSY_STATUSES = {'ACT': 'running', 'PEND': 'queued'}
# A firewall whose job check is older than this is checked again just before its next step; a
# firewall waiting in the queue behind a job is checked this often
BUSY_RECHECK = 60
# Seconds a download or install waits in the queue for a firewall's running jobs to finish before
# it's skipped (queue_timeout in config.yml; 0 skips busy firewalls straight away)
QUEUE_TIMEOUT = 1800
# Read-only checks (running jobs, free space, HA state) sent to this many firewalls at once
PRECHECK_PARALLEL = 16

# PAN-OS download safeguards (config.yml can change each; see the README). An image is downloaded
# into /opt/pancfg, then moved to /opt/panrepo while it's loaded into the software manager, so
# pancfg needs room for the largest image and panrepo for all of them. A firewall whose disk use
# would pass DISK_WARN_PERCENT is only included if you say so. Also: assumed size when the release
# list gives none, firewalls downloading at once, and failures that stop new downloads starting.
DISK_SPACE_CMD = '<show><system><disk-space></disk-space></system></show>'
PANCFG = '/opt/pancfg'
PANREPO = '/opt/panrepo'
DISK_WARN_PERCENT = 90
UNKNOWN_IMAGE_MB = 1500
MAX_PARALLEL_DOWNLOADS = 10
STOP_AFTER_FAILURES = 3
# '8.4G', '413M', '80K', '0' in df output
DISK_SIZE = re.compile(r'^(\d+(?:[.,]\d+)?)([KMGTPE]?)$', re.IGNORECASE)
# Job failures that mean something is wrong with the firewall itself, not with the request. They
# count towards stop_after_failures, and a firewall that had one isn't tried again this session
# without asking.
IMAGE_CORRUPT = re.compile(r'md5sum|checksums? did not match|authentication error|rpm internal error|'
                           r'region trailer|error reading package|corrupt', re.IGNORECASE)
MANAGEMENT_LOST = re.compile(r'actively refused|response was not xml|remote end closed|connection aborted|'
                             r'lost track of job', re.IGNORECASE)

# Config snapshots are saved on the firewall as <YYYY-MM-DD>.xml, and downloaded as
# <hostname>_<snapshot name>
SNAPSHOT_NAME = re.compile(r'^\d{4}-\d{2}-\d{2}\.xml$')
SNAPSHOT_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
# Completion point for 'show config saved <name>', which lists the saved snapshots
SAVED_CONFIGS_XPATH = '/operations/show/config/saved'
# Characters Windows doesn't allow in a file name
UNSAFE_FILE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# HA: this firewall's full HA detail (its own and its peer's: state, serial number, management
# IP, model, versions...). The tool never syncs HA config - that's done by hand on the firewall.
HA_STATE_CMD = '<show><high-availability><all></all></high-availability></show>'
# The active unit of a pair (listed first)
HA_ACTIVE_STATES = ('active', 'active-primary')

# Run logs: <log_folder>/<YYYY-MM-DD_HHMMSS>.log, and each action's results table as
# <log name>_<HHMMSS>_<action>.csv. Only files named like these are ever pruned.
LOG_NAME = re.compile(r'^\d{4}-\d{2}-\d{2}_\d{6}(?:_\d{6}_[a-z0-9-]+\.csv|\.log)$')

# Local data file: one row per firewall, keyed by serial number. Every value the tool can learn
# about a firewall has a column; a row needs only an IP or a hostname to connect. 'notes' is yours:
# the tool never changes it. Columns the tool doesn't know are kept as they are.
DATA_FILE = r'data\devices.csv'
DATA_FIELDS = [
    'serial', 'hostname', 'ip', 'port', 'mgmt_ip', 'model', 'family', 'vm_license',
    'sw_version', 'app_version', 'threat_version', 'av_version', 'wildfire_version', 'url_version',
    'ha_enabled', 'ha_mode', 'ha_state', 'ha_priority', 'ha_running_sync',
    'ha_peer_serial', 'ha_peer_hostname', 'ha_peer_mgmt_ip', 'ha_peer_state', 'ha_peer_model',
    'ha_peer_sw_version', 'ha_peer_conn_status',
    'last_seen', 'notes',
]
# Column names another file might use for the same values (case doesn't matter)
DATA_ALIASES = {
    'serial number': 'serial', 'serial-num': 'serial', 'sn': 'serial',
    'ip address': 'ip', 'address': 'ip', 'ip-address': 'ip', 'management ip': 'mgmt_ip',
    'name': 'hostname', 'host name': 'hostname', 'fqdn': 'hostname', 'device': 'hostname',
    'pan-os': 'sw_version', 'panos': 'sw_version', 'sw-version': 'sw_version',
}
# Columns that can hold either an IP or a hostname (sorted by the value)
DATA_EITHER = {'host', 'target', 'firewall'}
# system info field -> data column
SYSTEM_DATA_FIELDS = {
    'hostname': 'hostname', 'serial': 'serial', 'ip-address': 'mgmt_ip', 'model': 'model',
    'family': 'family', 'vm-license': 'vm_license', 'sw-version': 'sw_version',
    'app-version': 'app_version', 'threat-version': 'threat_version', 'av-version': 'av_version',
    'wildfire-version': 'wildfire_version', 'url-filtering-version': 'url_version',
}


# ---------------------------------------------------------------- run log

class RunLog:
    """Copies everything printed to the screen, and every answer typed, to a log file, each line
    with a timestamp. Passwords are read with getpass, which never passes through here."""

    def __init__(self, path):
        self.path = path
        self.file = open(path, 'a', encoding='utf-8')
        self.lock = threading.Lock()
        self.partial = ''
        # Set by screen_only(): what's printed meanwhile isn't logged
        self.paused = False
        self.streams = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = (_Tee(stream, self) for stream in self.streams)

    def record(self, text):
        """Add text to the log only (not the screen). Lines are written once they're complete."""
        with self.lock:
            if self.file.closed:
                return
            self.partial += text
            *lines, self.partial = self.partial.split('\n')
            for line in lines:
                self.file.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}  {line}\n")
            self.file.flush()

    def close(self):
        sys.stdout, sys.stderr = self.streams
        if self.partial:
            self.record('\n')
        with self.lock:
            self.file.close()


class _Tee:
    """A stand-in for sys.stdout or sys.stderr that also writes to the run log."""

    def __init__(self, stream, log):
        self.stream, self.log = stream, log

    def write(self, text):
        self.stream.write(text)
        if not self.log.paused:
            self.log.record(text)
        return len(text)

    def flush(self):
        self.stream.flush()

    def __getattr__(self, name):
        return getattr(self.stream, name)


LOG = None


def log_only(text):
    """Write a line to the run log without showing it."""
    if LOG:
        LOG.record(text + '\n')


@contextlib.contextmanager
def screen_only():
    """Show what's printed inside the block without writing it to the run log (log search results)."""
    if LOG:
        LOG.paused = True
    try:
        yield
    finally:
        if LOG:
            LOG.paused = False


def start_log(config):
    """Open this run's log file and prune logs older than log_retention_days. Returns the RunLog, or
    None if the folder can't be written to (the tool carries on without a log)."""
    folder = config_folder(config['log_folder'])
    try:
        folder.mkdir(parents=True, exist_ok=True)
        days = config['log_retention_days']
        if days:
            cutoff = time.time() - days * 86400
            for old in folder.iterdir():
                if LOG_NAME.match(old.name) and old.stat().st_mtime < cutoff:
                    old.unlink()
        log = RunLog(folder / f"{datetime.datetime.now():%Y-%m-%d_%H%M%S}.log")
    except OSError as e:
        print(f"WARNING: can't write the log file in {folder} ({e.strerror}) - carrying on without one.")
        return None
    print(f"Logging to {log.path}")
    return log


# ---------------------------------------------------------------- helpers

def ask(text):
    """input(), with the question and the answer also written to the run log.

    The question goes through print, so the log gets it whether or not the console is
    interactive; the typed answer is echoed by the console, so it's added to the log only.
    """
    print(text, end='', flush=True)
    answer = input()
    if LOG:
        LOG.record(answer + '\n')
    # An answer typed after the idle timeout disconnected the session goes back to the Main Menu
    ACTIVITY.check()
    ACTIVITY.touch()
    return answer


def config_folder(value):
    """A folder named in config.yml: environment variables (%USERPROFILE%) and ~ are expanded,
    and a relative path is relative to the tool's folder (the EXE's folder when frozen)."""
    path = Path(os.path.expandvars(os.path.expanduser(str(value))))
    return path if path.is_absolute() else BASE_DIR / path


def prompt(label, default=''):
    value = ask(f"{label} [{default}]: ").strip()
    return value or default


def parse_selection(text, choices, blocked):
    """Turn '3', '1,4,6', '2-5' or a mix like '1,3-5' into a sorted list of numbers.

    choices holds the numbers that can be picked; blocked maps listed numbers that can't
    be picked to the reason why. Raises ValueError saying what's wrong with the answer.
    """
    chosen = set()
    for part in text.split(','):
        match = SELECTION_PATTERN.match(part)
        if not match:
            raise ValueError(f"'{part.strip()}' isn't a number or a range like 2-4")
        start, end = int(match[1]), int(match[2] or match[1])
        if start > end:
            raise ValueError(f"Range {start}-{end} runs backwards")
        for number in range(start, end + 1):
            if number in blocked:
                raise ValueError(f"#{number} can't be selected: {blocked[number]}")
            if number not in choices:
                raise ValueError(f"#{number} isn't in the list")
        chosen.update(range(start, end + 1))
    return sorted(chosen)


def pick(label, choices, blocked=None, blank_means_all=True, explicit=False, single=False):
    """Ask for one or more numbers from choices ({number: item}) until the answer is valid.

    Blank picks everything, or nothing when blank_means_all is False. 'all' picks everything,
    unless explicit is set (each item has to be named, e.g. for deletes). single allows one
    number only. Explicit and single picks default to nothing.
    """
    blocked = blocked or {}
    blank_means_all = blank_means_all and not (explicit or single)
    default = 'all' if blank_means_all else 'none'
    hint = 'number' if single else 'number, list (1,3) or range (2-4)'
    while True:
        text = ask(f"{label} - {hint} [{default}]: ").strip().lower()
        if not text:
            return list(choices.values()) if blank_means_all else []
        if text == 'all':
            if explicit or single:
                print("  Pick one by number - 'all' isn't allowed here." if single
                      else "  Name each one by number - 'all' isn't allowed here.")
                continue
            return list(choices.values())
        try:
            numbers = parse_selection(text, choices, blocked)
            if single and len(numbers) > 1:
                raise ValueError("Pick one only")
            return [choices[n] for n in numbers]
        except ValueError as e:
            print(f"  {e}")


def confirm(question):
    return ask(f"{question} [y/N]: ").strip().lower() in ('y', 'yes')


def stage(title):
    print(f"\n=== {title} ===")


def menu(title, options, zero='Back'):
    """Show a numbered menu and return the chosen number as a string ('0' for back/exit).

    options is a list of labels, or None to leave a number out while keeping the others in place.
    """
    stage(title)
    valid = {'0'}
    for number, label in enumerate(options, 1):
        if label:
            print(f"{number} - {label}")
            valid.add(str(number))
    print(f"0 - {zero}")
    while True:
        choice = ask("Choice: ").strip()
        if choice in valid:
            return choice
        print(f"  Enter one of {', '.join(sorted(valid, key=int))}.")


def request_cmd(path, action):
    """'<request><content><upgrade><check></check></upgrade></content></request>' from (('content', 'upgrade'), 'check')."""
    outer, inner = path
    return f"<request><{outer}><{inner}><{action}></{action}></{inner}></{outer}></request>"


def print_table(rows, details=None):
    """Print dicts as aligned columns, leaving out columns that are '-' on every row.

    details, if given, holds one dict per row, printed on a second line under it in the
    same columns (e.g. release dates under versions).
    """
    columns = [c for c in rows[0] if any(row.get(c, '-') != '-' for row in rows)]
    lines = [[row.get(c, '') for c in columns] for row in rows]
    if details:
        lines = [line for pair in zip(lines, ([d.get(c, '') for c in columns] for d in details))
                 for line in pair]
    widths = [max(len(c), *(len(line[i]) for line in lines)) for i, c in enumerate(columns)]
    print('  '.join(c.ljust(w) for c, w in zip(columns, widths)).rstrip())
    print('  '.join('-' * w for w in widths))
    for line in lines:
        if any(line):
            print('  '.join(value.ljust(w) for value, w in zip(line, widths)).rstrip())


def short_date(text):
    match = DATE_PATTERN.search(text or '')
    return '-'.join(match.groups()) if match else '-'


def version_key(version):
    """Sort key for PAN-OS, content and GP versions: '9165-10321', '11.2.7-h8' and '6.2.8-c263' all work."""
    return tuple(int(n) for n in re.findall(r'\d+', version))


# ---------------------------------------------------------------- config

def config_number(config, key, default, low=0, high=None, zero_means_default=False, filename='config.yml'):
    """config[key] as a number between low and high, or default if it's missing or not a number
    (or 0, when zero_means_default). A value out of range is clamped, with a warning."""
    value = config.get(key)
    if value is None or value == '' or (zero_means_default and value == 0):
        return default
    if isinstance(value, bool):
        value = 'yes' if value else 'no'
    try:
        number = float(value)
    except (TypeError, ValueError):
        print(f"WARNING: {key} in {filename} isn't a number ({value!r}) - using {default}.")
        return default
    clamped = max(low, number if high is None else min(number, high))
    if clamped != number:
        print(f"WARNING: {key} {number:g} in {filename} is out of range - using {clamped:g}.")
    return int(clamped) if clamped == int(clamped) else clamped


ON_WORDS = {'on', 'yes', 'true', 'y', '1'}
OFF_WORDS = {'off', 'no', 'false', 'n', '0'}
# A 'severity' setting: what a health check reports when it finds that condition
SEVERITIES = ('warn', 'fail', 'off')
LIST_SEPARATOR = re.compile(r'\s*,\s*')


class Setting:
    """One config.yml (or health_checks.yaml) value: how it's read and how Settings edits it.

    kind: 'number' (a whole number from low to high; 0 means the default when zero_means_default),
    'text', 'path' (a file or folder; environment variables and relative paths allowed), 'ssl'
    (true, false or a CA bundle file), 'onoff', 'severity' (warn, fail or off) or 'list' (a comma
    separated list, saved as a YAML list). restart: only read when the tool starts.
    """

    def __init__(self, key, kind, default, help, low=0, high=None, zero_means_default=False, restart=False):
        self.key, self.kind, self.default, self.help = key, kind, default, help
        self.low, self.high, self.zero_means_default, self.restart = low, high, zero_means_default, restart

    def show(self, value):
        """The value as Settings shows it, inside [ ]."""
        if self.kind == 'onoff':
            return 'On' if value else 'Off'
        if self.kind == 'severity':
            return str(value).upper()
        if self.kind == 'list':
            return ', '.join(str(v) for v in value or [])
        if isinstance(value, bool):
            return 'true' if value else 'false'
        return '' if value is None else str(value)

    def limits(self):
        """'10 or more', '0 to 99' - for a number setting, else ''."""
        if self.kind != 'number':
            return ''
        span = f"{self.low} to {self.high}" if self.high is not None else f"{self.low} or more"
        return span + (' (0 = the default)' if self.zero_means_default else '')

    def parse(self, text):
        """The value typed for this setting, or ValueError saying what's wrong with it."""
        text = text.strip()
        if self.kind == 'number':
            if not re.fullmatch(r'\d+', text):
                raise ValueError(f"Enter a whole number, {self.limits()}.")
            number = int(text)
            if number == 0 and self.zero_means_default:
                return self.default
            if number < self.low or (self.high is not None and number > self.high):
                raise ValueError(f"{number} is out of range - enter {self.limits()}.")
            return number
        if self.kind == 'onoff':
            if text.lower() in ON_WORDS | OFF_WORDS:
                return text.lower() in ON_WORDS
            raise ValueError("Enter On or Off.")
        if self.kind == 'severity':
            if text.lower() in SEVERITIES:
                return text.lower()
            raise ValueError("Enter WARN, FAIL or OFF.")
        if self.kind == 'list':
            # Del gives the default; '-' empties the list
            return [] if text == '-' else [v.strip('"\'') for v in LIST_SEPARATOR.split(text) if v.strip('"\'')]
        if self.kind == 'ssl':
            if text.lower() in ('true', 'yes', 'on'):
                return True
            if text.lower() in ('false', 'no', 'off'):
                return False
            path = config_folder(text.strip('"'))
            if not path.is_file():
                raise ValueError(f"Enter true, false, or the path to a CA bundle - there's no file at {path}.")
            return text.strip('"')
        return text.strip('"') if self.kind == 'path' else text

    def read(self, raw, filename):
        """This setting's value from a loaded YAML file (raw), checked; the default, with a warning,
        if it's missing or not valid. For number, severity, onoff and list settings."""
        value = raw.get(self.key)
        if self.kind == 'number':
            return config_number(raw, self.key, self.default, self.low, self.high, self.zero_means_default,
                                 filename)
        if value is None or value == '':
            return self.default if self.kind != 'list' or value is None else []
        if self.kind == 'onoff':
            if str(value).lower() in ON_WORDS | OFF_WORDS:
                return str(value).lower() in ON_WORDS
        elif self.kind == 'severity':
            if str(value).lower() in SEVERITIES:
                return str(value).lower()
        elif self.kind == 'list':
            values = value if isinstance(value, list) else LIST_SEPARATOR.split(str(value))
            return [str(v).strip() for v in values if v is not None and str(v).strip()]
        else:
            return value
        print(f"WARNING: {self.key} in {filename} isn't valid ({value!r}) - using {self.show(self.default)}.")
        return self.default


# Settings > Application Settings categories (Main Menu option 7), in menu order. JumpHosts (5) has its own menu.
SETTING_CATEGORIES = {
    'Targets & Data': [
        Setting('default_target', 'text', '',
                "Offered at the Target prompt when no devices are known: one firewall, a comma separated list, "
                "or the path to a file with one per line."),
        Setting('data_file', 'path', DATA_FILE,
                "The local data file Load and Write offer, and Connect to Device(s) loads when no devices are "
                "known. A relative path is relative to the tool's (or the EXE's) folder."),
    ],
    'Connection': [
        Setting('verify_ssl', 'ssl', False,
                "false: no CA check (self-signed management certificates) - each firewall's certificate is "
                "trusted the first time it connects and has to match every time after (known_certs.txt); "
                "true checks each firewall's certificate against the system CA store; or the path to a CA "
                "bundle (.pem)."),
        Setting('keygen_timeout', 'number', 90,
                "Seconds to wait for keygen to answer - the time you have to approve the MFA push.",
                10, zero_means_default=True),
        Setting('request_timeout', 'number', 30,
                "Seconds to wait for any other API call. Also how long ssh waits to connect to a JumpHost.",
                5, zero_means_default=True),
        Setting('check_timeout', 'number', 120,
                "Seconds to wait for an update check or a log search, and for a JumpHost test to finish.",
                5, zero_means_default=True),
        Setting('keepalive_interval', 'number', KEEPALIVE_INTERVAL,
                "Seconds between keep-alive polls to each authenticated firewall. Keep it well below the "
                "firewall's admin Idle Timeout. 0 turns polling off.", 0, 3600),
        Setting('app_idle_timeout', 'number', APP_IDLE_TIMEOUT,
                "Minutes with no activity before the tool logs out, clears the API keys and returns to the Main Menu. "
                "0 never disconnects.", 0),
    ],
    'Jobs & Downloads': [
        Setting('job_timeout', 'number', 1800,
                "Seconds to wait for each download or install job to finish.", 60, zero_means_default=True),
        Setting('job_poll_interval', 'number', JOB_POLL_INTERVAL,
                "Seconds between status checks while a download or install job runs.",
                1, 300, zero_means_default=True),
        Setting('max_parallel_downloads', 'number', MAX_PARALLEL_DOWNLOADS,
                "Most firewalls downloading a PAN-OS image at once. 0 = no limit.", 0),
        Setting('disk_warn_percent', 'number', DISK_WARN_PERCENT,
                "Disk use (%) a PAN-OS download may bring /opt/pancfg or /opt/panrepo up to before you're asked "
                "whether to include the firewall. 0 skips the disk check.", 0, 99),
        Setting('queue_timeout', 'number', QUEUE_TIMEOUT,
                "Seconds a download or install waits for a job already running on a firewall. 0 skips a busy "
                "firewall instead.", 0, 86400),
        Setting('stop_after_failures', 'number', STOP_AFTER_FAILURES,
                "After this many firewalls fail in a way that points at the firewall, no more downloads start "
                "until you say so. 0 never stops.", 0),
        Setting('download_test_group', 'number', 0,
                "Default answer to 'how many firewalls to download to first'. 0 = all at once.", 0),
    ],
    'Files & Logs': [
        Setting('download_folder', 'path', r'%USERPROFILE%\Downloads',
                "Where config snapshots, system state backups and log search CSVs are saved."),
        Setting('log_folder', 'path', 'logs',
                "Where each run's log is written. A relative path is relative to the tool's folder.", restart=True),
        Setting('log_retention_days', 'number', 30,
                "Logs older than this many days are deleted at start-up. 0 keeps them all.", 0, restart=True),
    ],
}
# Shown in the JumpHosts menu
JUMP_CHAINING = Setting('jump_host_chaining', 'onoff', True,
                        "On: a JumpHost's ProxyJump (another JumpHost) is used, so a connection can pass through "
                        "several. Off: every JumpHost is connected to directly and ProxyJump is ignored.")
SETTINGS = {s.key: s for group in SETTING_CATEGORIES.values() for s in group}
SETTINGS[JUMP_CHAINING.key] = JUMP_CHAINING


def load_config():
    if not CONFIG_PATH.exists():
        print(f"Config file not found - creating {CONFIG_PATH} from the skeleton.")
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SKELETON_PATH, CONFIG_PATH)
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}

    # Older configs listed the firewalls under 'firewalls'
    old_list = [str(h).strip() for h in config.pop('firewalls', None) or [] if str(h).strip()]
    config['default_target'] = str(config.get('default_target') or ', '.join(old_list)).strip()
    # Management interfaces use self-signed certificates unless verify_ssl says otherwise
    if config.get('verify_ssl') is None:
        config['verify_ssl'] = False
    config.pop('download_space_factor', None)   # replaced by disk_warn_percent
    for setting in SETTINGS.values():
        if setting.kind == 'number':
            config[setting.key] = config_number(config, setting.key, setting.default, setting.low,
                                                setting.high, setting.zero_means_default)
        elif setting.kind == 'path':
            config[setting.key] = str(config.get(setting.key) or setting.default)
    chaining = config.get(JUMP_CHAINING.key)
    config[JUMP_CHAINING.key] = (JUMP_CHAINING.default if chaining is None
                                 else str(chaining).lower() in ON_WORDS)
    config['jump_hosts'] = read_jump_hosts(config.get('jump_hosts'))
    return config


# ---------------------------------------------------------------- health check thresholds

# health_checks.yaml: each health check's on/off switch and its WARN and FAIL thresholds, in the same
# flat key: value form as config.yml, edited under Settings > Health Check Thresholds
HEALTH_PATH = BASE_DIR / 'config' / 'health_checks.yaml'
HEALTH_SKELETON = BUNDLE_DIR / 'config' / 'skeleton_health_checks.yaml'
PERCENT = {'low': 0, 'high': 100}


def health_setting(check, name, kind, default, help, **limits):
    return Setting(f"{check}_{name}", kind, default, help, **limits)


def enabled_setting(check, what):
    return health_setting(check, 'enabled', 'onoff', True, f"On: Run Health Check {what}. Off: it's left out.")


# (key, menu label): the checks Run Health Check makes, in report order. Every setting of a check
# starts with its key; <key>_enabled turns it on or off.
HEALTH_CHECKS = [
    ('system_info', 'System Info'), ('chassis_leds', 'Chassis LEDs'), ('environment', 'Environmentals'),
    ('mp_resources', 'MP Resources'), ('dataplane', 'Dataplane'), ('sessions', 'Sessions'), ('ha', 'HA'),
    ('interfaces', 'Interfaces'), ('system_log', 'System Log'), ('log_forwarding', 'Log Forwarding'),
    ('panorama', 'Panorama'), ('licenses', 'Licenses'), ('disk', 'Disk'), ('pending_changes', 'Pending Changes'),
    ('jobs', 'Jobs'), ('certificates', 'Certificates'),
]
HEALTH_LABELS = dict(HEALTH_CHECKS)
SEVERITY_HELP = "WARN or FAIL, or OFF to leave it out."
HEALTH_CATEGORIES = {
    'System Info': [
        enabled_setting('system_info', 'reads show system info'),
        health_setting('system_info', 'uptime_warn_hours', 'number', 24,
                       "Uptime under this many hours is a WARN - a restart nobody planned? 0 = off.", low=0, high=8760),
        health_setting('system_info', 'uptime_fail_hours', 'number', 0,
                       "Uptime under this many hours is a FAIL. 0 = off.", low=0, high=8760),
        health_setting('system_info', 'device_certificate', 'severity', 'warn',
                       "The device certificate isn't Valid (cloud services need it). " + SEVERITY_HELP),
        health_setting('system_info', 'vm_license', 'severity', 'fail',
                       "A VM-Series firewall has no VM license. " + SEVERITY_HELP),
    ],
    'Chassis LEDs': [
        enabled_setting('chassis_leds', 'reads the chassis LEDs (hardware only)'),
        health_setting('chassis_leds', 'not_green', 'severity', 'fail',
                       "An LED that's red or amber, or the alarm LED on. " + SEVERITY_HELP),
        health_setting('chassis_leds', 'ignore', 'list', ['ha'],
                       "LEDs not checked, comma separated. ha is amber on a passive unit, so it's left out."),
    ],
    'Environmentals': [
        enabled_setting('environment', 'reads show system environmentals (hardware only)'),
        health_setting('environment', 'alarm', 'severity', 'fail',
                       "A temperature, fan or power sensor in alarm. " + SEVERITY_HELP),
        health_setting('environment', 'power_supply_missing', 'severity', 'warn',
                       "A power supply slot is empty - normal on a single-PSU install. " + SEVERITY_HELP),
        health_setting('environment', 'temp_margin_warn', 'number', 5,
                       "A temperature within this many degrees C of its sensor's maximum is a WARN. 0 = off.",
                       low=0, high=100),
    ],
    'MP Resources': [
        enabled_setting('mp_resources', 'reads the management plane CPU, memory and swap'),
        health_setting('mp_resources', 'cpu_warn', 'number', 70,
                       "Management CPU (1-minute average) %, at or over which it's a WARN. 0 = off.", **PERCENT),
        health_setting('mp_resources', 'cpu_fail', 'number', 80, "Management CPU % for a FAIL. 0 = off.", **PERCENT),
        health_setting('mp_resources', 'memory_warn', 'number', 85,
                       "Management memory used % (not counting buffers and cache) for a WARN. 0 = off.", **PERCENT),
        health_setting('mp_resources', 'memory_fail', 'number', 90, "Memory used % for a FAIL. 0 = off.", **PERCENT),
        health_setting('mp_resources', 'swap_warn', 'number', 1, "Swap used % for a WARN. 0 = off.", **PERCENT),
        health_setting('mp_resources', 'swap_fail', 'number', 0, "Swap used % for a FAIL. 0 = off.", **PERCENT),
    ],
    'Dataplane': [
        enabled_setting('dataplane', 'reads show running resource-monitor (the last 5 minutes)'),
        health_setting('dataplane', 'cpu_warn', 'number', 80,
                       "Dataplane CPU % (average of the cores over 5 minutes) for a WARN. 0 = off.", **PERCENT),
        health_setting('dataplane', 'cpu_fail', 'number', 90, "Dataplane CPU % for a FAIL. 0 = off.", **PERCENT),
        health_setting('dataplane', 'packet_buffer_warn', 'number', 50,
                       "Packet buffer use % (highest minute) for a WARN. 0 = off.", **PERCENT),
        health_setting('dataplane', 'packet_buffer_fail', 'number', 80, "Packet buffer % for a FAIL. 0 = off.",
                       **PERCENT),
        health_setting('dataplane', 'packet_descriptor_warn', 'number', 50,
                       "Packet descriptor use % (highest minute, on-chip included) for a WARN. 0 = off.", **PERCENT),
        health_setting('dataplane', 'packet_descriptor_fail', 'number', 80,
                       "Packet descriptor % for a FAIL. 0 = off.", **PERCENT),
    ],
    'Sessions': [
        enabled_setting('sessions', 'reads show session info'),
        health_setting('sessions', 'used_warn', 'number', 80,
                       "Active sessions as % of the maximum, for a WARN. 0 = off.", **PERCENT),
        health_setting('sessions', 'used_fail', 'number', 90, "Session table % for a FAIL. 0 = off.", **PERCENT),
    ],
    'HA': [
        enabled_setting('ha', 'reads show high-availability all, and shows the HA pairs'),
        health_setting('ha', 'state', 'severity', 'fail',
                       "This unit isn't active or passive (suspended, non-functional...), or both units are "
                       "active. " + SEVERITY_HELP),
        health_setting('ha', 'peer_down', 'severity', 'fail', "The peer isn't connected. " + SEVERITY_HELP),
        health_setting('ha', 'ha1_down', 'severity', 'fail', "The HA1 (control) link is down. " + SEVERITY_HELP),
        health_setting('ha', 'ha2_down', 'severity', 'warn', "The HA2 (data) link is down. " + SEVERITY_HELP),
        health_setting('ha', 'backup_link_down', 'severity', 'warn',
                       "A configured HA1 or HA2 backup link is down. " + SEVERITY_HELP),
        health_setting('ha', 'config_sync', 'severity', 'warn',
                       "The running config isn't synchronized with the peer. " + SEVERITY_HELP),
        health_setting('ha', 'version_mismatch', 'severity', 'warn',
                       "PAN-OS, content or another version doesn't match the peer's. " + SEVERITY_HELP),
    ],
    'Interfaces': [
        enabled_setting('interfaces', 'reads show interface all'),
        health_setting('interfaces', 'down', 'severity', 'warn',
                       "An interface with a zone, IP or virtual router configured whose port is down. "
                       "Tunnel, loopback, VLAN, HA and management interfaces aren't checked. " + SEVERITY_HELP),
        health_setting('interfaces', 'ignore', 'list', [],
                       "Interfaces not checked, comma separated (e.g. ethernet1/8). A port leaves out its "
                       "subinterfaces too."),
    ],
    'System Log': [
        enabled_setting('system_log', 'searches the System log for high and critical entries'),
        health_setting('system_log', 'hours', 'number', 24, "How far back to search, in hours.", low=1, high=720),
        health_setting('system_log', 'high_warn', 'number', 1,
                       "This many high entries or more is a WARN. 0 = off.", low=0),
        health_setting('system_log', 'high_fail', 'number', 0, "High entries for a FAIL. 0 = off.", low=0),
        health_setting('system_log', 'critical_warn', 'number', 0, "Critical entries for a WARN. 0 = off.", low=0),
        health_setting('system_log', 'critical_fail', 'number', 1,
                       "This many critical entries or more is a FAIL. 0 = off.", low=0),
        health_setting('system_log', 'exclude_eventids', 'list', [],
                       "Event IDs not counted (known noise), comma separated, e.g. general, auth-fail."),
    ],
    'Log Forwarding': [
        enabled_setting('log_forwarding', 'reads show logging-status'),
        health_setting('log_forwarding', 'not_forwarding', 'severity', 'warn',
                       "Logs aren't being forwarded to Panorama, a Log Collector or the logging service. "
                       + SEVERITY_HELP),
    ],
    'Panorama': [
        enabled_setting('panorama', 'reads show panorama-status'),
        health_setting('panorama', 'disconnected', 'severity', 'fail',
                       "A configured Panorama isn't connected. " + SEVERITY_HELP),
    ],
    'Licenses': [
        enabled_setting('licenses', 'reads request license info (installed licenses; nothing is fetched)'),
        health_setting('licenses', 'expiry_warn_days', 'number', 30,
                       "A license with this many days left or fewer is a WARN. 0 = off.", low=0, high=3650),
        health_setting('licenses', 'expiry_fail_days', 'number', 0,
                       "Days left for a FAIL. An expired license is always a FAIL. 0 = only expired.",
                       low=0, high=3650),
        health_setting('licenses', 'ignore', 'list', [],
                       "Licenses not checked, by feature name, comma separated."),
    ],
    'Disk': [
        enabled_setting('disk', 'reads show system disk-space'),
        health_setting('disk', 'used_warn', 'number', 85, "A partition this % full or more is a WARN. 0 = off.",
                       **PERCENT),
        health_setting('disk', 'used_fail', 'number', 95, "Partition % full for a FAIL. 0 = off.", **PERCENT),
        health_setting('disk', 'panrepo_free_fail_gb', 'number', 3,
                       "/opt/panrepo with less than this many GB free is a FAIL (room for a PAN-OS image). 0 = off.",
                       low=0),
        health_setting('disk', 'ignore', 'list', ['/opt/panlogs'],
                       "Partitions not checked, comma separated. /opt/panlogs runs full by design (the oldest "
                       "logs are purged)."),
    ],
    'Pending Changes': [
        enabled_setting('pending_changes', 'runs check pending-changes'),
        health_setting('pending_changes', 'uncommitted', 'severity', 'warn',
                       "The candidate config has changes that aren't committed. " + SEVERITY_HELP),
    ],
    'Jobs': [
        enabled_setting('jobs', 'reads show jobs all'),
        health_setting('jobs', 'hours', 'number', 24, "How far back a failed job counts, in hours.", low=1, high=720),
        health_setting('jobs', 'failed', 'severity', 'warn', "A job failed in that time. " + SEVERITY_HELP),
        health_setting('jobs', 'running_warn_minutes', 'number', 60,
                       "A job still running after this many minutes is a WARN. 0 = off.", low=0),
    ],
    'Certificates': [
        enabled_setting('certificates', 'reads the certificates in the firewall\'s own config (shared and vsys)'),
        health_setting('certificates', 'expiry_warn_days', 'number', 30,
                       "A certificate with this many days left or fewer is a WARN. 0 = off.", low=0, high=3650),
        health_setting('certificates', 'expiry_fail_days', 'number', 0,
                       "Days left for a FAIL. An expired certificate is always a FAIL. 0 = only expired.",
                       low=0, high=3650),
        health_setting('certificates', 'ignore', 'list', [],
                       "Certificates not checked, by name, comma separated."),
    ],
}
HEALTH_SETTINGS = {s.key: s for group in HEALTH_CATEGORIES.values() for s in group}


def load_health_checks():
    """health_checks.yaml as {key: value}, every value checked (a missing or bad one is the default,
    with a warning). Created from the skeleton the first time. Read each time it's used, so a change
    made to the file by hand applies to the next health check."""
    raw = {}
    try:
        if not HEALTH_PATH.exists():
            print(f"Health check thresholds not found - creating {HEALTH_PATH} from the skeleton.")
            HEALTH_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HEALTH_SKELETON, HEALTH_PATH)
        with open(HEALTH_PATH, 'r', encoding='utf-8') as f:
            raw = yaml.safe_load(f) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        print(f"WARNING: can't read {HEALTH_PATH} ({getattr(e, 'strerror', None) or e}) - using the default thresholds.")
    if not isinstance(raw, dict):
        print(f"WARNING: {HEALTH_PATH.name} isn't a list of key: value settings - using the default thresholds.")
        raw = {}
    return {s.key: s.read(raw, HEALTH_PATH.name) for s in HEALTH_SETTINGS.values()}


# config.yml is written by Settings a value at a time. Only the changed keys' lines are replaced,
# so every comment stays; the file as it was before each change is kept as config.yml.bak.
CONFIG_BACKUP = CONFIG_PATH.with_name(CONFIG_PATH.name + '.bak')
TOP_KEY = re.compile(r'^([A-Za-z_][\w-]*)\s*:')
LIST_ITEM = re.compile(r'^-(\s|$)')


def backup_of(path):
    """Where Settings keeps the copy of path before each change: config.yml.bak, health_checks.yaml.bak."""
    return CONFIG_BACKUP if path == CONFIG_PATH else path.with_name(path.name + '.bak')


class ConfigWriteError(Exception):
    pass


def config_blocks(lines):
    """Where each top-level key's block is in config.yml's lines: ({key: (first, end)}, keys that
    appear more than once). A block is the key's line plus the indented lines under it."""
    blocks, repeated = {}, set()
    i = 0
    while i < len(lines):
        match = TOP_KEY.match(lines[i])
        if not match:
            i += 1
            continue
        start = last = i
        i += 1
        # The key's own lines: indented, blank, or a block-style list item ('- x' at column 0)
        while i < len(lines) and (not lines[i].strip() or lines[i][0] in ' \t' or LIST_ITEM.match(lines[i])):
            if lines[i].strip():
                last = i
            i += 1
        if match[1] in blocks:
            repeated.add(match[1])
        blocks[match[1]] = (start, last + 1)
        i = last + 1
    return blocks, repeated


def config_yaml(key, value):
    """key: value as YAML lines. A list is written on one line, [a, b]."""
    return yaml.safe_dump({key: value}, sort_keys=False, default_flow_style=None if isinstance(value, list) else False,
                          allow_unicode=True, width=1000)


def write_config_values(updates, path=None):
    """Write {key: value} to config.yml (or path): each key's own lines are replaced (a key the file
    doesn't have is added at the end), so comments and the other values are left exactly as they were.
    The result is read back and checked before it replaces the file, and the old file is kept as
    config.yml.bak (backup_of). Raises ConfigWriteError (nothing written) if that can't be done safely."""
    path = path or CONFIG_PATH
    try:
        # Read as bytes so a CRLF file is seen as CRLF (read_text would turn it into LF)
        text = path.read_bytes().decode('utf-8')
        before = yaml.safe_load(text) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise ConfigWriteError(f"can't read {path}: {getattr(e, 'strerror', None) or e}")
    newline = '\r\n' if '\r\n' in text else '\n'
    lines = text.splitlines(keepends=True)
    blocks, repeated = config_blocks(lines)
    if repeated & updates.keys():
        raise ConfigWriteError(f"{', '.join(sorted(repeated & updates.keys()))} appears more than once in "
                               f"{path.name} - fix the file by hand first")
    added = []
    # Bottom of the file first, so the line numbers of blocks still to replace don't move
    for key in sorted((k for k in updates if k in blocks), key=lambda k: blocks[k][0], reverse=True):
        start, end = blocks[key]
        lines[start:end] = config_yaml(key, updates[key]).replace('\n', newline).splitlines(keepends=True)
    for key in updates:
        if key not in blocks:
            added.append(config_yaml(key, updates[key]).replace('\n', newline))
    new_text = ''.join(lines)
    if added:
        if new_text and not new_text.endswith(('\n', '\r\n')):
            new_text += newline
        new_text += newline + ''.join(added)
    try:
        after = yaml.safe_load(new_text) or {}
    except yaml.YAMLError as e:
        raise ConfigWriteError(f"the changed file wouldn't read back ({e}) - nothing written")
    if after != {**before, **updates}:
        raise ConfigWriteError("the changed file didn't read back as expected - nothing written")
    try:
        shutil.copyfile(path, backup_of(path))
        temp = path.with_name(path.name + '.tmp')
        temp.write_text(new_text, encoding='utf-8', newline='')
        os.replace(temp, path)
    except OSError as e:
        raise ConfigWriteError(f"can't write {path}: {e.strerror}")


def save_settings(config, updates, path=None):
    """Write the changed values to config.yml (or path) and use them for the rest of this run.
    Returns True if they were written."""
    try:
        write_config_values(updates, path)
    except ConfigWriteError as e:
        print(f"Not saved: {e}.")
        return False
    config.update(updates)
    if updates.get('verify_ssl') is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return True


# ---------------------------------------------------------------- key-at-a-time input

# What read_key_line returns, besides the text, for Esc and Delete
ESC, DEL = 'esc', 'del'
# What edit_value returns when Esc is pressed
CANCEL = object()


def read_key_line(text):
    """Ask for a line on the console a key at a time, so Esc and Delete can be told apart from text.
    Returns (typed text, None) on Enter, (None, ESC) on Esc, or (None, DEL) on Delete. The prompt and
    what's typed are shown, and logged, as with ask(). Without a console (input piped in) it reads an
    ordinary line instead."""
    if not sys.stdin.isatty():
        return ask(text), None
    import msvcrt
    # Echoed to the screen only; the finished line goes to the log once, at the end
    screen = sys.stdout.stream if isinstance(sys.stdout, _Tee) else sys.stdout

    def show(s):
        screen.write(s)
        screen.flush()

    show(text)
    chars, key, ending = [], None, ''
    while True:
        ch = msvcrt.getwch()
        if ch in '\r\n':
            break
        if ch == '\x03':
            show('\n')
            raise KeyboardInterrupt
        if ch == '\x1b':
            key, ending = ESC, '  (Esc - cancelled)'
            break
        if ch in '\x00\xe0':
            # A special key: Delete is 'S'; arrows and the rest are ignored
            if msvcrt.getwch() == 'S':
                key, ending = DEL, '  (Del - default)'
                break
            continue
        if ch == '\x08':
            if chars:
                chars.pop()
                show('\b \b')
            continue
        if ch.isprintable():
            chars.append(ch)
            show(ch)
    show(ending + '\n')
    line = ''.join(chars)
    log_only(f"{text}{line}{ending}")
    ACTIVITY.check()
    ACTIVITY.touch()
    return (None, key) if key else (line, None)


EDIT_HINT = "Type a new value and press Enter to save it. Enter alone keeps the [value], Esc cancels, Del reverts to the default."


def edit_value(label, current, default, parse=None, show=str, required=False):
    """Ask for a value with the [current] one shown: Enter keeps it, Delete gives default, Esc gives
    CANCEL, and anything typed goes through parse (which raises ValueError to ask again). A required
    value can't be left blank."""
    while True:
        text, key = read_key_line(f"{label} [{show(current)}]: ")
        if key == ESC:
            return CANCEL
        if key == DEL:
            value = default
        elif not text.strip():
            value = current
        else:
            try:
                value = parse(text.strip()) if parse else text.strip()
            except ValueError as e:
                print(f"  {e}")
                continue
        if required and value in (None, ''):
            print(f"  {label} is required.")
            continue
        return value


# ---------------------------------------------------------------- device database

def data_column(name):
    """A data file column name in the tool's spelling ('Serial Number' -> 'serial'), or None for a
    column the tool doesn't know."""
    key = ' '.join(str(name or '').strip().lower().replace('_', ' ').split())
    for column in DATA_FIELDS:
        if key == column.replace('_', ' '):
            return column
    return DATA_ALIASES.get(key) or (key if key in DATA_EITHER else None)


def same_address(a, b):
    """Whether two IP values (with or without :port) are the same address."""
    return bool(a) and bool(b) and a.split(':')[0] == b.split(':')[0]


class DeviceDB:
    """Every firewall the tool knows about in this run, keyed by serial number - serial numbers are
    unique, unlike hostnames or addresses. Each device is a dict of data file columns (DATA_FIELDS,
    plus any other columns its data file row had). Rows that have no serial number yet (from a data
    file, for a firewall not connected to so far) wait in .unkeyed until a connection learns it.

    Held in memory only: Write Local Data File saves it. It never holds credentials or API keys.
    .source is the data file last loaded or written (the default for both next time), and .changed
    says connections have added to it since."""

    def __init__(self):
        self.devices = {}
        self.unkeyed = []
        self.source = None
        self.changed = False

    def __len__(self):
        return len(self.devices) + len(self.unkeyed)

    def clear(self):
        self.devices.clear()
        self.unkeyed.clear()
        self.changed = False

    def rows(self):
        return list(self.devices.values()) + list(self.unkeyed)

    def match(self, serial=None, ip=None, hostname=None):
        """The known row for a firewall: by serial number if given, else by IP, else by hostname."""
        if serial and serial in self.devices:
            return self.devices[serial]
        rows = self.rows()
        if ip:
            found = next((r for r in rows if same_address(r.get('ip'), ip) or same_address(r.get('mgmt_ip'), ip)), None)
            if found:
                return found
        if hostname:
            return next((r for r in rows if same_hostname(r.get('hostname'), hostname)), None)
        return None

    def add_row(self, row):
        """Add a data file row (columns already in the tool's spelling). A serial number already
        known is merged (blank values don't overwrite). Returns the row it ended up in."""
        row = {k: v for k, v in row.items() if v not in (None, '')}
        serial = row.get('serial')
        if serial:
            device = self.devices.setdefault(serial, {})
            for key, value in row.items():
                device.setdefault(key, value)
            return device
        existing = self.match(ip=row.get('ip'), hostname=row.get('hostname'))
        if existing is not None and not existing.get('serial'):
            for key, value in row.items():
                existing.setdefault(key, value)
            return existing
        self.unkeyed.append(row)
        return row

    def record(self, fw):
        """Store what fw reported (it must be authenticated, with its serial number known), merged
        into what was known: the firewall's values replace the tool's columns; 'notes' and columns
        the tool doesn't know are kept. A row known only by fw's IP or hostname is absorbed."""
        if not fw.serial:
            return None
        self.changed = True
        device = self.devices.get(fw.serial)
        if device is None:
            device = {}
            loose = self.match(ip=fw.ip, hostname=fw.hostname)
            if loose is not None and not loose.get('serial') and loose in self.unkeyed:
                self.unkeyed.remove(loose)
                device.update(loose)
            self.devices[fw.serial] = device
        # The target list's own row for it (notes, your columns) - unless it names another serial
        if fw.known.get('serial') in (None, '', fw.serial):
            for key, value in fw.known.items():
                device.setdefault(key, value)
        values = device_values(fw)
        if device.get('ha_peer_serial') != values.get('ha_peer_serial', device.get('ha_peer_serial')):
            device.pop('ha_peer_hostname', None)   # a different peer now
        device.update(values)
        # The peer's hostname, if the peer is known by its serial number
        peer = self.devices.get(device.get('ha_peer_serial'))
        if peer and peer.get('hostname'):
            device['ha_peer_hostname'] = peer['hostname']
        for other in self.devices.values():
            if other.get('ha_peer_serial') == fw.serial and fw.hostname:
                other['ha_peer_hostname'] = fw.hostname
        return device


DEVICES = DeviceDB()


def device_values(fw):
    """A connected firewall's values as data file columns: its address, show system info, HA."""
    values = {'serial': fw.serial, 'ip': fw.ip, 'port': '' if fw.port == DEFAULT_PORT else str(fw.port),
              **fw.system, 'last_seen': f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}"}
    if fw.ha is not None:
        values['ha_enabled'] = 'yes' if fw.ha['enabled'] else 'no'
        if fw.ha['enabled']:
            local, peer = fw.ha['local'], fw.ha['peer']
            values.update({
                'ha_mode': fw.ha.get('mode', ''), 'ha_state': local.get('state', ''),
                'ha_priority': local.get('priority', ''), 'ha_running_sync': fw.ha.get('running_sync', ''),
                'ha_peer_serial': peer.get('serial', ''), 'ha_peer_mgmt_ip': peer.get('mgmt_ip', ''),
                'ha_peer_state': peer.get('state', ''), 'ha_peer_model': peer.get('model', ''),
                'ha_peer_sw_version': peer.get('PAN-OS', ''), 'ha_peer_conn_status': peer.get('conn', ''),
            })
            if fw.peer is not None and fw.peer.hostname:
                values['ha_peer_hostname'] = fw.peer.hostname
        else:
            for column in DATA_FIELDS:
                if column.startswith('ha_') and column != 'ha_enabled':
                    values[column] = ''
    return {k: v for k, v in values.items() if v is not None}


def data_path(config):
    """The data file Load and Write offer: the one last loaded or written this run, else data_file
    (None if neither)."""
    return DEVICES.source or (config_folder(config['data_file']) if config.get('data_file') else None)


def read_data_rows(path):
    """The rows of a data file with a header row, as dicts in the tool's column spelling. Columns
    the tool doesn't know keep their own name. Returns (rows, header)."""
    import csv
    with open(path, newline='', encoding='utf-8-sig') as f:
        # Parsed as CSV first, so a quoted cell can hold several lines (Alt+Enter in Excel) - blank ones
        # and ones starting with # included. Only then are blank rows and # comment rows left out.
        records = [values for values in csv.reader(f)
                   if any(value.strip() for value in values) and not values[0].lstrip().startswith('#')]
    header = records[0] if records else []
    names = [data_column(h) or h.strip() for h in header]
    rows = []
    for values in records[1:]:
        row = {}
        for name, value in zip(names, values):
            value = value.strip()
            if not name or not value:
                continue
            if name in DATA_EITHER:
                # An IP or a hostname, sorted by what it looks like
                kind = parse_field(value).get('kind')
                name = 'ip' if kind == 'ip' else 'hostname'
                if name in row:
                    continue
            row[name] = value
        if row:
            rows.append(row)
    return rows, [n for n in names if n]


def has_data_header(line):
    """Whether a target file's first line is a header row naming at least one known column."""
    import csv
    fields = next(csv.reader([line]), [])
    return any(data_column(f) or f.strip().lower() in HEADER_WORDS for f in fields)


# ---------------------------------------------------------------- targets

def read_target_input(text):
    """Work out whether the input is a file, a list or one firewall. Returns (description, rows):
    each row is a list of one or two fields (see read_target_file)."""
    text = text.strip().strip('"\'')
    if FILE_PATTERN.search(text):
        path = Path(text).expanduser()
        rows = read_target_file(path)
        return f"File {path} ({len(rows)} entries)", rows
    rows = [[e] for e in LIST_SEPARATORS.split(text) if e]
    if len(rows) > 1:
        return f"List of {len(rows)} firewalls", rows
    return "Single firewall", rows


def read_target_file(path):
    """One firewall per line: its IP address, its hostname, or both separated by a comma (either
    order). Returns one list of fields per line.

    Blank lines and # comments are skipped. A line with more than two fields (a CSV export) is read
    as its first field, plus the second when that's the other kind of value.

    A file whose first line names known columns (a data file, see DATA_FIELDS) is read by those
    columns instead: each row is a dict, with at least an IP or a hostname to connect to, and any
    other values it has are checked against what the firewall reports.
    """
    text = path.read_text(encoding='utf-8-sig')
    first = next((line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')), '')
    if first and has_data_header(first):
        data_rows, _ = read_data_rows(path)
        return data_rows
    rows = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        fields = [f.strip().strip('"\'') for f in LIST_SEPARATORS.split(line)]
        fields = [f for f in fields if f]
        if not fields:
            continue
        if not rows and fields[0].lower() in HEADER_WORDS:
            continue
        rows.append(fields)
    return rows


def parse_field(text):
    """One field of a target row: {'kind': 'ip' or 'name', 'value', 'port'} or {'error'}."""
    match = ENTRY_PATTERN.match(text)
    if not match:
        return {'error': f"'{text}' is not a hostname or IP address"}
    value = match['name'].rstrip('.')
    port = int(match['port']) if match['port'] else None
    if port is not None and not 1 <= port <= 65535:
        return {'error': f"'{text}': port must be 1-65535"}
    if IPV4_PATTERN.match(value):
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return {'error': f"'{text}' is not a valid IPv4 address"}
        return {'kind': 'ip', 'value': value, 'port': port}
    if not HOSTNAME_PATTERN.match(value):
        return {'error': f"'{text}' is not a valid hostname"}
    return {'kind': 'name', 'value': value, 'port': port}


def resolve_target(fields):
    """Check one target row - an IPv4 address, a hostname, or one of each - and look a hostname up in
    DNS when there's no IP. A row with both connects to the IP; its hostname is what the firewall's
    own hostname is checked against once connected.

    Returns {'entry', 'ip', 'name', 'host' (what to connect to, with :port if one was given), 'port',
    'address' (the IP, given or looked up), 'type', 'error', 'known'}. A data file row (a dict) is
    read by its ip, hostname and port columns, and kept whole as 'known'.
    """
    known = None
    if isinstance(fields, dict):
        known = fields
        port = known.get('port', '')
        fields = [v for v in (known.get('ip'), known.get('hostname')) if v]
        if fields and port and ':' not in fields[0]:
            fields[0] = f"{fields[0]}:{port}"
        if not fields:
            return {'entry': ', '.join(f"{k}={v}" for k, v in list(known.items())[:3]), 'ip': None, 'name': None,
                    'host': '', 'port': DEFAULT_PORT, 'type': '-', 'address': '-', 'known': known,
                    'error': 'No IP or hostname on this line - one is needed to connect'}
        target = resolve_target(fields)
        target['known'] = known
        return target
    if isinstance(fields, str):
        fields = [fields]
    target = {'entry': ', '.join(fields), 'ip': None, 'name': None, 'host': fields[0] if fields else '',
              'port': DEFAULT_PORT, 'type': '-', 'address': '-', 'error': None}
    parsed = [parse_field(f) for f in fields[:2]]
    if not parsed:
        target['error'] = 'Empty line'
        return target
    if 'error' in parsed[0]:
        target['error'] = parsed[0]['error']
        return target
    if len(parsed) == 2:
        first, second = parsed
        if 'error' in second or second['kind'] == first['kind']:
            if len(fields) > 2:
                # A CSV export's other columns: only the first field is the firewall
                parsed = [first]
            elif 'error' in second:
                target['error'] = second['error']
                return target
            else:
                kind = 'IP addresses' if first['kind'] == 'ip' else 'hostnames'
                target['error'] = f"Two {kind} ({target['entry']}) - a line holds an IP, a hostname, or one of each"
                return target

    values = {p['kind']: p for p in parsed}
    ports = {p['port'] for p in parsed if p['port'] is not None}
    if len(ports) > 1:
        target['error'] = f"The IP and the hostname give different ports ({target['entry']})"
        return target
    ip, name = values.get('ip'), values.get('name')
    target['ip'] = ip['value'] if ip else None
    target['name'] = name['value'] if name else None
    connect = target['ip'] or target['name']
    if ports:
        target['port'] = ports.pop()
        target['host'] = f"{connect}:{target['port']}"
    else:
        target['host'] = connect

    if ip:
        target['address'] = ip['value']
        target['type'] = 'IP + hostname' if name else 'IP'
        return target
    target['type'] = 'Hostname'
    try:
        infos = socket.getaddrinfo(target['name'], target['port'], type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        # Windows reports every lookup failure as 'getaddrinfo failed', so say which it was
        reason = {socket.EAI_NONAME: 'name not found', socket.EAI_AGAIN: 'DNS server did not answer'}
        target['error'] = f"DNS lookup failed: {reason.get(e.errno, e.strerror)}"
        return target
    addresses = [info[4][0] for info in infos]
    target['address'] = next((a for a in addresses if ':' not in a), addresses[0])
    target['type'] = 'Hostname (DNS)'
    return target


def same_hostname(a, b):
    """Whether two hostnames name the same firewall: equal ignoring case, or one is the other's short
    name (fw01 and fw01.example.com)."""
    if not a or not b:
        return False
    a, b = a.lower().rstrip('.'), b.lower().rstrip('.')
    return a == b or a.split('.')[0] == b or b.split('.')[0] == a


def check_targets(rows):
    """Number and resolve every row, flagging ones that point at a firewall already in the list - the
    same address and port, or the same hostname."""
    targets, seen, names = [], {}, {}
    for number, fields in enumerate(rows, 1):
        target = resolve_target(fields)
        target['number'] = number
        if not target['error']:
            key = (target['address'], target['port'])
            name = (target['name'] or '').lower()
            if key in seen:
                target['error'] = f"Same firewall as #{seen[key]}"
            elif name and name in names:
                target['error'] = f"Same hostname as #{names[name]}"
            else:
                seen[key] = number
                if name:
                    names[name] = number
        targets.append(target)
    return targets


def target_rows(targets):
    """The Targets table: what each row gave, and what will be read from the firewall."""
    rows = []
    for t in targets:
        if t['error']:
            ip, name = t['ip'] or '-', t['name'] or '-'
        else:
            port = f":{t['port']}" if t['port'] != DEFAULT_PORT else ''
            ip = t['ip'] + port if t['ip'] else f"{t['address']}{port} (DNS)"
            name = t['name'] or '(read on connect)'
        rows.append({'#': str(t['number']), 'IP': ip, 'Hostname': name, 'Status': t['error'] or 'OK'})
    return rows


def choose_targets(config):
    """Stage 1: ask for the firewalls, work out what kind of input it is, and check each one.

    When the device database is empty, the local data file is loaded into it first; otherwise what's
    in memory (a file you loaded, plus devices connected to this run) is used as it is. When devices
    are known, they're the default (KNOWN_TARGET), and a single number picks one by its View Devices
    number. Firewalls connected to from a list or file are added to the device database
    (record_devices), so Write Local Data File can save them.
    """
    stage('Targets')
    if not len(DEVICES) and data_path(config):
        load_data_file(config, data_path(config), missing_note=False)
    devices = device_list()
    if devices:
        print(f"Enter a device number from View Devices (1-{len(devices)}), one firewall, a comma separated "
              f"list, or the path to a file with one per line (IP, hostname, or IP,hostname).\n"
              f"Enter connects to the {len(devices)} known device(s).")
        default = KNOWN_TARGET
    else:
        print("Enter one firewall, a comma separated list, or the path to a file with one per line "
              "(IP, hostname, or IP,hostname).")
        default = config['default_target']
    while True:
        text = prompt('Target', default).strip()
        default = ''
        if not text:
            return []
        if devices and text.lower() == KNOWN_TARGET:
            description, entries = f"Known devices ({len(devices)})", list(devices)
        elif INDEX_PATTERN.match(text):
            index = int(text)
            if not devices:
                print("There are no known devices to pick by number - Load Local Data File first, or enter "
                      "an IP or hostname.")
                continue
            if not 1 <= index <= len(devices):
                print(f"There's no device #{index} - View Devices lists 1-{len(devices)}.")
                continue
            description, entries = f"Device #{index} from View Devices", [devices[index - 1]]
        else:
            try:
                description, entries = read_target_input(text)
            except OSError as e:
                print(f"Could not read {e.filename}: {e.strerror}")
                continue
            except UnicodeDecodeError:
                print("Could not read the file - it isn't a text file.")
                continue
        if not entries:
            print("No firewalls found in that input.")
            continue

        print(f"\n{description}:")
        targets = check_targets(entries)
        print_table(target_rows(targets))
        if any(not t['error'] and not t['name'] for t in targets):
            print("Hostnames not in the list are read from each firewall when it connects.")

        usable = {t['number']: t for t in targets if not t['error']}
        if not usable:
            print("\nNone of those targets can be used. Try again, or press Enter to quit.")
            continue
        if len(usable) == 1:
            return list(usable.values())
        blocked = {t['number']: t['error'] for t in targets if t['error']}
        print()
        selected = pick('Select firewalls', usable, blocked)
        print(f"Selected {len(selected)} of {len(targets)}: "
              + ', '.join(f"#{t['number']}" for t in selected))
        return selected


# ---------------------------------------------------------------- XML API

class PanError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def parse_response(response):
    """Return the <response> element, or raise PanError with the firewall's message."""
    if response.is_redirect:
        raise PanError(f"HTTP {response.status_code} redirect to {response.headers.get('Location')} "
                       f"- not followed", response.status_code)
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError:
        raise PanError(f"HTTP {response.status_code}, response was not XML", response.status_code)
    if root.get('status') != 'success':
        messages = [' '.join(''.join(m.itertext()).split()) for m in root.iter('msg')]
        message = '; '.join(m for m in messages if m) or f"HTTP {response.status_code}"
        raise PanError(message, response.status_code)
    return root


class PinnedAdapter(requests.adapters.HTTPAdapter):
    """Accepts only the one certificate whose SHA-256 is fingerprint. urllib3 checks it during the TLS
    handshake of every connection - direct or through a proxy - before the request (credentials
    included) is sent, so a different certificate gets nothing."""

    def __init__(self, fingerprint, **kwargs):
        # Set first: HTTPAdapter.__init__ calls init_poolmanager
        self.fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['assert_fingerprint'] = self.fingerprint
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs['assert_fingerprint'] = self.fingerprint
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class Firewall:
    """One firewall's XML API session. Its API key lives only in this object's headers."""

    def __init__(self, target, config):
        self.number = target['number']
        self.host = target['host']
        # Shown in the Firewall column: the IP connected to (given, or looked up for a hostname)
        address = target.get('address')
        port = target.get('port', DEFAULT_PORT)
        self.port = port
        if address and address != '-':
            self.ip = address
            self.name = address if port == DEFAULT_PORT else f"{address}:{port}"
        else:
            self.ip = self.host.rsplit(':', 1)[0] if self.host.count(':') == 1 else self.host
            self.name = target['entry']
        # What the data file (or the device database) already knows about this firewall - matched by
        # the target row itself, or by its IP or hostname. Checked against what it reports.
        self.known = dict(target.get('known') or DEVICES.match(ip=self.ip, hostname=target.get('name')) or {})
        # The hostname the target list gave (or the data file knows): checked against the firewall's
        # own once connected
        self.expected_hostname = target.get('name') or self.known.get('hostname') or None
        self.url = f"https://{self.host}/api/"
        self.timeout = (CONNECT_TIMEOUT, config['request_timeout'])
        self.keygen_timeout = (CONNECT_TIMEOUT, config['keygen_timeout'])
        self.check_timeout = (CONNECT_TIMEOUT, config['check_timeout'])
        self.job_timeout = config['job_timeout']
        # How long a download or install waits for this firewall's running jobs (run_jobs)
        self.queue_timeout = config.get('queue_timeout', 0)
        self.poll_interval = config['job_poll_interval']
        self.session = requests.Session()
        self.session.verify = config['verify_ssl']
        # Exactly one attempt per call: a retried keygen would send another MFA push
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=0))
        # With verify_ssl false, nothing is sent until the firewall's certificate is pinned
        # (check_certificates, pin): its SHA-256, checked on every connection after that
        self.needs_pin = config['verify_ssl'] is False
        self.fingerprint = None
        self.auth_result = None
        self.auth_reason = ''
        # The admin whose key this is: Disconnect logs that admin's sessions out (logout)
        self.username = None
        # Latest update check per kind (content type or PAN-OS): list of releases, used by the
        # install and download options
        self.updates = {}
        # Name of the config snapshot saved this session, if any
        self.snapshot = None
        # From show system info at authentication: used to name downloads, label the firewall
        # everywhere and match HA peers
        self.hostname = None
        self.serial = None
        # Every show system info value kept, by data file column (SYSTEM_DATA_FIELDS)
        self.system = {}
        self.mgmt_ip = None
        self.model = None
        self.sw_version = None
        # Differences between the target list and what the firewall reported, and HA pairing
        # problems, found at authentication (review_inventory)
        self.notes = []
        # Its HA peer, when that's in this session's list (correlate_ha)
        self.peer = None
        # HA state (parse_ha), read at authentication and by Run Health Check; None if it couldn't be read
        self.ha = None
        # One request at a time, shared with the keep-alive thread; last_used is when the
        # firewall last heard from this session
        self.lock = threading.Lock()
        self.last_used = time.monotonic()
        # Why keep-alive polls to this firewall stopped (a poll failed), or None. Cleared once a
        # real request gets a reply.
        self.keepalive_stopped = None
        # Why this session's PAN-OS download to it failed in a way that points at the firewall (a
        # corrupt image, or its management stopping), or didn't get an answer. A later download asks
        # before trying it again.
        self.download_failure = None

    def __str__(self):
        name = self.hostname or self.expected_hostname
        if name and name != self.name:
            return f"#{self.number} {name} ({self.name})"
        return f"#{self.number} {self.name}"

    @property
    def authenticated(self):
        return 'X-PAN-KEY' in self.session.headers

    def keygen(self, username, password):
        self.check_pinned()
        with self.lock:
            self.forget_key()
            # Credentials go in the POST body so they never land in a URL, proxy log or access log.
            # Redirects aren't followed: that would re-send them, and trigger another MFA push.
            response = self.session.post(
                self.url,
                data={'type': 'keygen', 'user': username, 'password': password},
                timeout=self.keygen_timeout,
                allow_redirects=False,
            )
            self.last_used = time.monotonic()
        ACTIVITY.touch()
        self.keepalive_stopped = None
        key = parse_response(response).findtext('result/key')
        if not key:
            raise PanError('keygen succeeded but returned no key')
        self.session.headers['X-PAN-KEY'] = key
        self.username = username

    def send(self, data, timeout=None):
        """Send one API request with the key and return the raw HTTP response."""
        if not self.authenticated:
            raise PanError(f"not authenticated - {self.auth_reason or 'no API key'}")
        self.check_pinned()
        ACTIVITY.touch()
        with self.lock:
            response = self.session.post(self.url, data=data, timeout=timeout or self.timeout,
                                         allow_redirects=False)
            self.last_used = time.monotonic()
        # A long request counts as activity for as long as it runs
        ACTIVITY.touch()
        # The firewall answered, so polling can start again
        self.keepalive_stopped = None
        return response

    def parse(self, response):
        """The <response> element of a reply. A reply saying the session has ended drops the key."""
        try:
            return parse_response(response)
        except PanError as e:
            if SESSION_ENDED.search(str(e)):
                self.session_ended(e)
            raise

    def post(self, data, timeout=None):
        """Send one API request with the key and return the <response> element."""
        return self.parse(self.send(data, timeout))

    def op(self, cmd, timeout=None):
        # A malformed command is a bug in this tool; catch it here rather than send it
        try:
            ET.fromstring(cmd)
        except ET.ParseError as e:
            raise PanError(f"tool error - this command isn't valid XML ({e}), so it wasn't sent: {cmd}")
        return self.post({'type': 'op', 'cmd': cmd}, timeout).find('result')

    def export(self, category, timeout=None):
        """A type=export download, e.g. category=device-state. Returns the file's bytes. Raises
        PanError if the firewall replies with an XML message instead of a file."""
        response = self.send({'type': 'export', 'category': category}, timeout or self.check_timeout)
        body = response.content
        if response.is_redirect or response.status_code != 200 or body.lstrip()[:9] == b'<response':
            self.parse(response)
            raise PanError(f"the firewall sent a message instead of a file: {message_text(ET.fromstring(body))}")
        if not body:
            raise PanError('the firewall sent an empty file')
        return body

    def read_ha(self):
        """Read the firewall's HA state into self.ha (see parse_ha) and return it."""
        self.ha = parse_ha(self.op(HA_STATE_CMD))
        return self.ha

    def saved_snapshots(self):
        """Names of the configuration snapshots saved on the firewall - the list the CLI offers
        for 'show config saved <Tab>', read with the XML API's complete action."""
        errors = []
        for request_type in ('op', 'config'):
            try:
                root = self.post({'type': request_type, 'action': 'complete', 'xpath': SAVED_CONFIGS_XPATH})
            except PanError as e:
                if not self.authenticated:
                    raise
                errors.append(f"type={request_type}: {e}")
                continue
            names = [e.get('value') for e in root.iter() if e.get('value')]
            if not names:
                # Shown so an unexpected reply format can be spotted and handled
                reply = ' '.join(ET.tostring(root, encoding='unicode').split())
                raise PanError(f"no snapshots listed - the firewall replied {reply[:300]}")
            return names
        raise PanError(f"could not list snapshots ({'; '.join(errors)})")

    def keep_alive(self):
        """Send one keep-alive poll, unless another request is in flight (which keeps the session
        open by itself). Nothing is printed or logged, and it doesn't count as activity for the
        application idle timeout.

        A poll that fails is never repeated, because a lapsed session makes the firewall log the
        admin in again - an MFA push - on every call:
        - refused (Credential Expired, Invalid Credential, HTTP 403): the key is dropped and the
          firewall marked EXPIRED, for Retry Authentication;
        - anything else, including no reply in time (a busy management plane, or an MFA push
          waiting): polls to it stop until a real request gets a reply. The key is kept, so a slow
          firewall doesn't lose its session, or the jobs being watched on it.
        """
        if not self.authenticated or self.keepalive_stopped or not self.lock.acquire(blocking=False):
            return
        try:
            response = self.session.post(self.url, data={'type': 'op', 'cmd': KEEPALIVE_CMD},
                                         timeout=self.timeout, allow_redirects=False)
            self.last_used = time.monotonic()
        except requests.ReadTimeout:
            self.keepalive_stopped = (f"no reply to a poll within {self.timeout[1]}s - the firewall may be "
                                      f"busy, or waiting on an MFA push")
            return
        except requests.RequestException as e:
            self.keepalive_stopped = connection_error_text(e)
            return
        finally:
            self.lock.release()
        try:
            parse_response(response)
        except PanError as e:
            if SESSION_ENDED.search(str(e)) or is_rejection(e):
                self.session_ended(e)
            else:
                self.keepalive_stopped = str(e)

    def session_ended(self, error):
        """The firewall ended the admin session behind the key (idle timeout, key lifetime, or
        Expire All API Keys). The key won't work again, so drop it and mark the firewall for
        Retry authentication."""
        self.forget_key()
        self.auth_result = EXPIRED
        self.auth_reason = f"session ended on the firewall ({error}) - use Retry authentication"

    def system_info(self, timeout=None):
        system = self.op('<show><system><info></info></system></show>', timeout).find('system')
        if system is None:
            raise PanError('show system info returned no <system> element')
        return system

    def releases(self, cmd, timeout=None):
        """Run a check/info command and return its release list, newest first.

        Each release is a dict of the entry's fields (version, released-on, downloaded,
        current, ...). Works for content updates and software (PAN-OS, GP client) lists.
        """
        result = self.op(cmd, timeout)
        if result is None:
            return []
        releases = [{child.tag: (child.text or '').strip() for child in entry}
                    for entry in result.iter('entry') if entry.find('version') is not None]
        return sorted(releases, key=lambda r: version_key(r['version']), reverse=True)

    @staticmethod
    def request_path(kind):
        return PANOS_REQUEST if kind == PANOS else CONTENT_TYPES[kind][0]

    def check_updates(self, kind):
        """Ask the firewall to fetch the current release list for PAN-OS or one content type from Palo Alto."""
        releases = self.releases(request_cmd(self.request_path(kind), 'check'), self.check_timeout)
        self.updates[kind] = merge_duplicates(releases) if kind == PANOS else releases
        return self.updates[kind]

    def cached_releases(self, kind):
        """The firewall's copy of the release list from its last check. Doesn't contact Palo Alto."""
        releases = self.releases(request_cmd(self.request_path(kind), 'info'))
        return merge_duplicates(releases) if kind == PANOS else releases

    def running_jobs(self):
        """The jobs queued or running on the firewall, newest first: [(id, type, status)], status
        being ACT (running) or PEND (queued). Includes jobs started outside this tool."""
        result = self.op(JOBS_ALL_CMD)
        jobs = []
        for job in result.iter('job') if result is not None else ():
            status = (job.findtext('status') or '').strip().upper()
            if status in JOB_BUSY_STATUSES:
                jobs.append(((job.findtext('id') or '').strip(), (job.findtext('type') or '').strip() or 'job', status))
        return sorted(jobs, key=lambda job: int(job[0]) if job[0].isdigit() else 0, reverse=True)

    def disk_space(self):
        """{mount point: free MB} from show system disk-space."""
        result = self.op(DISK_SPACE_CMD)
        return parse_disk_space(''.join(result.itertext()) if result is not None else '')

    def panos_release_date(self, version):
        """Release date of a PAN-OS version. Empty until a software check has been run on the firewall."""
        for release in self.cached_releases(PANOS):
            if release['version'] == version:
                return release.get('released-on')
        return None

    def confirm_key(self):
        """Make the first call with the new key.

        PAN-OS logs a remote (RADIUS) admin in again the first time a new key is used, which
        sends a second MFA push. Doing it here keeps both pushes in the authentication stage;
        later calls reuse that login and don't push. The reply's hostname and serial number are kept.
        """
        system = self.system_info(timeout=self.keygen_timeout)
        self.system = {column: (system.findtext(tag) or '').strip() for tag, column in SYSTEM_DATA_FIELDS.items()}
        self.system = {column: value for column, value in self.system.items() if value}
        self.hostname = self.system.get('hostname')
        self.serial = self.system.get('serial')
        self.mgmt_ip = self.system.get('mgmt_ip')
        self.model = self.system.get('model')
        self.sw_version = self.system.get('sw_version')

    def logout(self, timeout=None, wait=None):
        """End this admin's sessions on the firewall (delete admin-sessions), then drop the key.

        PAN-OS has no logout for a single API session, so this ends every session the admin has on
        the firewall - the web UI and SSH included. wait is how long to wait for a request already
        in flight (None waits for it). The key is dropped whatever the outcome; raises PanError or
        requests.RequestException if the firewall didn't confirm it.
        """
        cmd = (f"<delete><admin-sessions><username>{escape(self.username or '')}</username>"
               f"</admin-sessions></delete>")
        ET.fromstring(cmd)
        if not self.lock.acquire(timeout=-1 if wait is None else wait):
            self.forget_key()
            raise PanError("another request to it was still running")
        try:
            response = self.session.post(self.url, data={'type': 'op', 'cmd': cmd},
                                         timeout=(min(CONNECT_TIMEOUT, timeout), timeout) if timeout else self.timeout,
                                         allow_redirects=False)
            self.last_used = time.monotonic()
        finally:
            self.forget_key()
            self.lock.release()
        try:
            parse_response(response)
        except PanError as e:
            # The delete can end the session it arrived on before the reply is written
            if not SESSION_ENDED.search(str(e)):
                raise

    def forget_key(self):
        self.session.headers.pop('X-PAN-KEY', None)

    def pin(self, fingerprint):
        """Accept only this certificate (SHA-256, hex) from now on, checked during every TLS handshake."""
        self.session.mount('https://', PinnedAdapter(fingerprint, max_retries=0))
        self.fingerprint = fingerprint

    def check_pinned(self):
        """With verify_ssl false, refuse to send anything before the certificate is pinned."""
        if self.needs_pin and not self.fingerprint:
            raise PanError("its certificate hasn't been checked - nothing sent")

    def close(self):
        self.forget_key()
        self.session.close()


class IdleDisconnect(Exception):
    """Raised at the next prompt after the application idle timeout has disconnected the session."""


class Activity:
    """When the user or the tool last did something: an answer typed at a prompt, or a request
    sent to a firewall. Keep-alive polls don't count. Drives app_idle_timeout."""

    def __init__(self):
        self.last = time.monotonic()
        self.disconnected = threading.Event()
        # Above 0 while something outside the tool's prompts has the user's attention (an SSH
        # session): the idle timeout waits
        self.held = 0

    def touch(self):
        self.last = time.monotonic()

    def check(self):
        """Raise IdleDisconnect if the idle timeout has disconnected the session."""
        if self.disconnected.is_set():
            raise IdleDisconnect()

    @contextlib.contextmanager
    def hold(self):
        """Pause the idle timeout for the duration, then count its end as activity."""
        self.held += 1
        try:
            yield
        finally:
            self.held -= 1
            self.touch()


ACTIVITY = Activity()


class Credentials:
    """The username and password from Authentication, kept in memory for Connect via SSH until the
    Disconnect (the Disconnect option, Exit, or the idle timeout). Never logged or written anywhere.

    The password is only kept once a firewall has accepted it, and SSH only fills it in for the
    firewalls that did (accepted) - a firewall that rejected or skipped the login gets no attempt
    with it, so it can't count towards an account lockout.
    """

    def __init__(self):
        self.clear()

    def clear(self):
        self.username = None
        self.password = None
        self.accepted = set()

    def keep(self, username, password, accepted):
        """After an Authentication: accepted lists the firewalls whose keygen took this password."""
        if not accepted:
            if self.password is None:
                self.username = username
            return
        if (username, password) != (self.username, self.password):
            # A different login replaces the old one; only the firewalls that took it can use it
            self.username, self.password, self.accepted = username, password, set()
        self.accepted.update(accepted)

    def fills(self, fw):
        return self.password is not None and fw in self.accepted


CREDENTIALS = Credentials()


class KeepAlive:
    """Keep-alive worker: a background thread that, every keepalive_interval seconds, polls every
    authenticated firewall in parallel with show system info, and disconnects the session after
    app_idle_timeout of no activity.

    For a remote (RADIUS) admin, PAN-OS ties the API key to an admin session, which the
    firewall's admin idle timeout ends. After that the key is refused ('Credential Expired'), or
    the next call logs the admin in again with a new MFA push. Polling keeps those sessions open,
    so you authenticate (and approve MFA) once, and stay connected until you disconnect or go idle.

    It starts before authentication, so each firewall is polled as soon as its key works, and
    stops at Disconnect. Every thread is a daemon, so none can outlive the tool.
    Each poll runs in its own short-lived thread, so a firewall that doesn't answer never delays the
    others; a firewall is never polled twice at once, nor while another request to it is in flight.
    A poll that fails is never repeated (see Firewall.keep_alive), so a lapsed session can't turn
    into a stream of MFA pushes.
    """

    def __init__(self, firewalls, interval, idle_timeout=0):
        self.firewalls = firewalls
        self.interval = interval
        # Seconds of no activity before the session is disconnected; 0 never disconnects
        self.idle_timeout = idle_timeout
        self.next_poll = time.monotonic() + interval
        self.stopped = threading.Event()
        self.in_flight = set()
        self.in_flight_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(KEEPALIVE_PARALLEL)
        self.error = None
        self.thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def stop(self, wait=CONNECT_TIMEOUT):
        """Stop polling. Polls already sent finish on their own (Firewall.logout waits for them)."""
        self.stopped.set()
        if self.thread and self.thread.is_alive() and self.thread is not threading.current_thread():
            self.thread.join(timeout=wait)

    def start(self):
        if self.interval or self.idle_timeout:
            self.thread = threading.Thread(target=self.run, name='keep-alive', daemon=True)
            self.thread.start()

    def check(self):
        """Restart the worker if it has died. Returns a message saying so, or None if it's running."""
        if (not (self.interval or self.idle_timeout) or self.stopped.is_set()
                or (self.thread and self.thread.is_alive())):
            return None
        reason = self.error or 'unknown reason'
        self.error = None
        self.start()
        return f"The keep-alive worker stopped ({reason}) and has been restarted."

    def run(self):
        try:
            # Wakes every few seconds; polls are sent once every interval
            while not self.stopped.wait(min(self.interval or KEEPALIVE_WAKE, KEEPALIVE_WAKE)):
                self.tick()
        except BaseException as e:
            self.error = f"{type(e).__name__}: {e}"

    def tick(self):
        now = time.monotonic()
        if self.idle_timeout and not ACTIVITY.held and now - ACTIVITY.last >= self.idle_timeout:
            self.disconnect()
            return
        if not self.interval or now < self.next_poll:
            return
        self.next_poll = now + self.interval
        for fw in self.firewalls:
            if self.stopped.is_set():
                return
            if not fw.authenticated or fw.keepalive_stopped:
                continue
            with self.in_flight_lock:
                if fw in self.in_flight:
                    continue
                if not self.slots.acquire(blocking=False):
                    return  # all slots busy; the rest are polled next time
                self.in_flight.add(fw)
            threading.Thread(target=self.ping, args=(fw,), name=f"keep-alive {fw.name}", daemon=True).start()

    def disconnect(self):
        """The application idle timeout: Disconnect (log out of every firewall, clear the keys and
        the password), and make the next prompt return to the Main Menu."""
        self.stopped.set()
        ACTIVITY.disconnected.set()
        minutes = self.idle_timeout / 60
        print(f"\n\nNo activity for {minutes:g} minute(s) - disconnecting.")
        disconnect('application idle timeout')
        print("Press Enter to return to the Main Menu.")

    def ping(self, fw):
        try:
            fw.keep_alive()
        except Exception:
            # One bad reply must never stop the keep-alive; the next real call reports any problem
            pass
        finally:
            with self.in_flight_lock:
                self.in_flight.discard(fw)
            self.slots.release()


def ident(fw):
    """The first columns of every per-firewall table: number, the IP connected to, and the hostname
    (the firewall's own once connected, else the one the target list gave)."""
    return {'#': str(fw.number), 'Firewall': fw.name, 'Hostname': fw.hostname or fw.expected_hostname or '-'}


def connection_error_text(error):
    """The OS-level reason from a requests error, without urllib3's pool and retry wrapping."""
    if 'Fingerprints did not match' in str(error):
        # PinnedAdapter refused the connection during the TLS handshake, before anything was sent
        return (f"its certificate isn't the one trusted for it in {CERTS_PATH.name} - possible interception, "
                f"nothing sent")
    match = re.search(r"\[(?:WinError|Errno) -?\d+\] ([^'\")]+)", str(error))
    return match.group(1).strip() if match else str(error)


# ---------------------------------------------------------------- HA state

# <local-info> / <peer-info> fields read from show high-availability all
HA_UNIT_FIELDS = {
    'state': 'state', 'serial': 'serial-num', 'mgmt_ip': 'mgmt-ip', 'conn': 'conn-status',
    'model': 'model', 'priority': 'priority',
    'PAN-OS': 'build-rel', 'Apps & Threats': 'app-version', 'Antivirus': 'av-version',
}


def parse_ha(result):
    """The parts of a show high-availability all (or state) reply the tool uses:
    {'enabled', 'mode', 'local': {...}, 'peer': {...}, 'running_sync'}. 'local' and 'peer' hold
    each unit's state, serial number, management IP and versions (HA_UNIT_FIELDS), plus every
    other single value the firewall reports for that unit under 'all' (model, priority, HA1
    address...), keyed by its tag."""
    if result is None or (result.findtext('enabled') or '').strip().lower() != 'yes':
        return {'enabled': False}
    group = result.find('group')
    if group is None:
        group = result

    def unit(element):
        if element is None:
            return {}
        values = {key: (element.findtext(tag) or '').strip() for key, tag in HA_UNIT_FIELDS.items()}
        values['state'] = values['state'].lower()
        # '10.0.0.1/24' -> '10.0.0.1'
        values['mgmt_ip'] = values['mgmt_ip'].split('/')[0]
        values['all'] = {child.tag: (child.text or '').strip() for child in element
                         if len(child) == 0 and (child.text or '').strip()}
        return values

    local = group.find('local-info')
    return {
        'enabled': True,
        'mode': (group.findtext('mode') or (local.findtext('mode') if local is not None else '') or '').strip(),
        'local': unit(local),
        'peer': unit(group.find('peer-info')),
        'running_sync': (group.findtext('running-sync') or '').strip().lower(),
    }


def state_text(state):
    """'active-primary' -> 'Active-Primary'."""
    return '-'.join(part.capitalize() for part in state.split('-')) if state else 'Unknown'


def ha_label(fw):
    """HA_Active, HA_Passive or Standalone - or HA_ plus any other state the firewall reports
    (HA_Active-Primary, HA_Suspended, HA_Non-Functional...). '-' if the state couldn't be read."""
    if fw.ha is None:
        return '-'
    if not fw.ha['enabled']:
        return 'Standalone'
    return f"HA_{state_text(fw.ha['local'].get('state'))}"


def poll_ha(fw):
    """Read the HA state after authentication. A failure only leaves the state unknown."""
    try:
        fw.read_ha()
    except (PanError, requests.RequestException) as e:
        fw.ha = None
        print(f"{fw}: could not read the HA state: {connection_error_text(e)}")


# ---------------------------------------------------------------- certificates

# known_certs.txt: the certificates trusted on first use while verify_ssl is false
CERTS_HEADER = (
    f"# {APP_TITLE}: firewall management certificates, trusted the first time each one connected\n"
    "# (verify_ssl: false). Every later connection to that address has to present the same certificate\n"
    "# (its SHA-256), or the tool refuses it before anything is sent. One per line: <address>:<port> <sha256>.\n"
    "# If a certificate was replaced on purpose (renewed, or a replacement firewall), delete its line and\n"
    "# connect again to trust the new one.\n"
)
FINGERPRINT = re.compile(r'^[0-9a-f]{64}$')


def pin_key(fw):
    """How fw's certificate is filed in known_certs.txt: the address the API connects to, and its port."""
    return f"{ssh_host(fw).lower()}:{fw.port}"


def certificate_fingerprint(fw):
    """The SHA-256 (hex) of the certificate fw's management interface presents. Nothing is sent; the
    certificate isn't checked against any CA."""
    pem = ssl.get_server_certificate((ssh_host(fw), fw.port), timeout=CONNECT_TIMEOUT)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def read_pins():
    """{'address:port': sha256} from known_certs.txt - empty if it doesn't exist yet."""
    try:
        lines = CERTS_PATH.read_text(encoding='utf-8').splitlines()
    except FileNotFoundError:
        return {}
    pins = {}
    for line in lines:
        fields = line.split('#', 1)[0].split()
        if len(fields) == 2 and FINGERPRINT.match(fields[1].lower()):
            pins[fields[0].lower()] = fields[1].lower()
    return pins


def add_pins(new):
    """Add {'address:port': sha256} to known_certs.txt (created with an explanation the first time)."""
    try:
        text = CERTS_PATH.read_text(encoding='utf-8')
    except FileNotFoundError:
        text = CERTS_HEADER
    if text and not text.endswith('\n'):
        text += '\n'
    text += ''.join(f"{address} {fingerprint}\n" for address, fingerprint in new.items())
    CERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = CERTS_PATH.with_name(CERTS_PATH.name + '.tmp')
    temp.write_text(text, encoding='utf-8')
    os.replace(temp, CERTS_PATH)


def check_certificates(firewalls):
    """verify_ssl false: pin each firewall's certificate before anything is sent to it (trust on first
    use). A certificate seen before (known_certs.txt) has to be the same one; new ones are listed and
    trusted only if you say so. Returns the firewalls that can go on to authenticate; the rest are marked
    FAIL (changed, or unreadable) or SKIPPED (not trusted), with the reason."""
    pending = [fw for fw in firewalls if fw.needs_pin and not fw.fingerprint]
    if not pending:
        return firewalls
    try:
        pins = read_pins()
    except (OSError, UnicodeDecodeError) as e:
        stage('Certificates')
        problem = f"can't read {CERTS_PATH} ({getattr(e, 'strerror', None) or e})"
        print(f"verify_ssl is false and {problem}, so nothing is sent to {len(pending)} firewall(s) until it "
              f"can be read.")
        for fw in pending:
            fw.auth_result, fw.auth_reason = FAIL, f"{problem} to check its certificate - nothing sent"
        return [fw for fw in firewalls if fw not in pending]
    stopped = set()

    def stop(fw, result, reason):
        fw.auth_result, fw.auth_reason = result, reason
        stopped.add(fw)

    new, changed, failed = {}, {}, {}
    for fw, outcome in parallel(certificate_fingerprint, pending).items():
        if isinstance(outcome, Exception):
            reason = (f"no answer within {CONNECT_TIMEOUT}s" if isinstance(outcome, TimeoutError)
                      else connection_error_text(outcome))
            failed[fw] = reason
            stop(fw, FAIL, f"could not read its certificate: {reason}")
        elif pin_key(fw) not in pins:
            new[fw] = outcome
        elif pins[pin_key(fw)] != outcome:
            changed[fw] = (pins[pin_key(fw)], outcome)
            stop(fw, FAIL, f"its certificate has CHANGED since it was trusted - possible interception, nothing "
                           f"sent. If it was replaced on purpose, delete the {pin_key(fw)} line in "
                           f"{CERTS_PATH.name} and connect again")
        else:
            fw.pin(outcome)
    if new or changed or failed:
        stage('Certificates')
        print(f"verify_ssl is false, so each firewall's certificate is trusted the first time it connects and "
              f"has to match every time after ({CERTS_PATH}).")
    for fw, reason in failed.items():
        print(f"{fw}: could not read its certificate: {reason}")
    if changed:
        print(f"\nCHANGED since you trusted it - nothing is sent to these ({len(changed)}):")
        for fw, (was, now) in changed.items():
            print(f"  {fw}:\n    trusted {was}\n    now     {now}")
        print(f"If a certificate was replaced on purpose (renewed, or a replacement firewall), delete its line in "
              f"{CERTS_PATH} and connect again. Otherwise something may be intercepting the connection.")
    if new:
        print(f"\nNot seen before ({len(new)}) - check a fingerprint against the firewall's certificate if you "
              f"can (the web UI's, in your browser):")
        print_table([{**ident(fw), 'SHA-256 fingerprint': fingerprint} for fw, fingerprint in new.items()])
        if confirm(f"Trust {'this certificate' if len(new) == 1 else f'these {len(new)} certificates'}?"):
            try:
                add_pins({pin_key(fw): fingerprint for fw, fingerprint in new.items()})
            except OSError as e:
                print(f"Could not save them to {CERTS_PATH} ({e.strerror}) - they're trusted for this run only.")
            for fw, fingerprint in new.items():
                fw.pin(fingerprint)
        else:
            for fw in new:
                stop(fw, SKIPPED, "its certificate wasn't trusted - nothing sent")
    return [fw for fw in firewalls if fw not in stopped]


# ---------------------------------------------------------------- authentication

def is_rejection(error):
    return isinstance(error, PanError) and (
        error.status_code == 403 or 'invalid credential' in str(error).lower())


def failure_reason(error, config, first_use=False):
    """Turn a keygen (or first-use) exception into a one-line reason a person can act on."""
    if first_use:
        if is_rejection(error):
            return f"Key generated, but rejected on first use ({error}) - the second MFA push was denied or expired"
        return f"Key generated, but failed on first use: {failure_reason(error, config)}"
    if isinstance(error, PanError):
        if is_rejection(error):
            return f"Rejected ({error}) - wrong password, or the MFA push was denied or expired"
        return f"Firewall error: {error}"
    if isinstance(error, requests.exceptions.SSLError):
        return f"TLS handshake failed: {connection_error_text(error)}"
    if isinstance(error, requests.ConnectTimeout):
        return f"Management interface did not answer within {CONNECT_TIMEOUT}s"
    if isinstance(error, requests.ReadTimeout):
        return f"No reply within {config['keygen_timeout']}s - MFA push not approved in time"
    if isinstance(error, requests.ConnectionError):
        return f"Could not connect: {connection_error_text(error)}"
    return f"{type(error).__name__}: {error}"


def authenticate(firewalls, config):
    """Stage 2: ask for credentials once, then on each firewall in turn generate a key and use it once.

    Every MFA push happens here, one firewall at a time, so the later stages never wait on one.
    A firewall only passes once its key has been accepted. Once a firewall has accepted the
    password, it's kept in memory for Connect via SSH (CREDENTIALS) until Disconnect
    (the Disconnect option, Exit, or the idle timeout); retrying asks for it again. With verify_ssl
    false, each firewall's certificate is checked (pinned) first, before the password is asked for.
    """
    firewalls = check_certificates(firewalls)
    if not firewalls:
        return
    stage('Authentication')
    username = prompt('Username', getpass.getuser())
    password = getpass.getpass('Password: ')
    log_only('Password: (not logged)')
    try:
        ACTIVITY.check()
    except IdleDisconnect:
        del password
        raise
    ACTIVITY.touch()
    # The firewalls whose keygen accepted this password
    accepted = []
    try:
        rejected = None
        for fw in firewalls:
            if rejected:
                fw.auth_result = SKIPPED
                fw.auth_reason = f"Not tried after {rejected} rejected the login, to avoid an account lockout"
                print(f"\n{fw}: {fw.auth_result} - {fw.auth_reason}")
                continue
            print(f"\n{fw}: keygen request sent - approve the MFA push "
                  f"(waiting up to {config['keygen_timeout']}s)...")
            # How long each request took, to compare with when the pushes arrived
            timings = []
            started = time.monotonic()
            first_use = False
            try:
                fw.keygen(username, password)
                accepted.append(fw)
                timings.append(f"keygen {time.monotonic() - started:.0f}s")
                print(f"{fw}: API key generated - confirming it works. "
                      f"Approve the MFA push if a second one arrives...")
                first_use = True
                started = time.monotonic()
                fw.confirm_key()
                timings.append(f"first use {time.monotonic() - started:.0f}s")
            except (PanError, requests.RequestException) as e:
                fw.forget_key()
                fw.auth_result, fw.auth_reason = FAIL, failure_reason(e, config, first_use)
                # A rejected keygen means the password is wrong everywhere
                if not first_use and is_rejection(e):
                    rejected = fw
            else:
                fw.auth_result, fw.auth_reason = PASS, 'API key generated and accepted'
                poll_ha(fw)
            if timings:
                fw.auth_reason += f" ({', '.join(timings)})"
            print(f"{fw}: {fw.auth_result} - {fw.auth_reason}")
    finally:
        CREDENTIALS.keep(username, password, accepted)
        # Python can't wipe a str in place; CREDENTIALS now holds the only copy, if any firewall took it
        del password


def hostname_note(fw):
    """A note when the hostname the target list gave isn't the one the firewall reports."""
    if fw.expected_hostname and fw.hostname and not same_hostname(fw.expected_hostname, fw.hostname):
        return f"hostname is {fw.hostname}, the list says {fw.expected_hostname} - check the list"
    return None


def known_data_notes(fw):
    """Differences between what the data file knew about fw and what it reports now, for the values
    that identify it or its HA pair: serial number, HA on or off, and the HA peer's serial number."""
    known, notes = fw.known, []
    if known.get('serial') and fw.serial and known['serial'] != fw.serial:
        notes.append(f"serial number is {fw.serial}, the data file says {known['serial']} - a different "
                     f"firewall answers at this address")
    if fw.ha is None:
        return notes
    if known.get('ha_enabled') in ('yes', 'no') and known['ha_enabled'] != ('yes' if fw.ha['enabled'] else 'no'):
        notes.append(f"HA is {'on' if fw.ha['enabled'] else 'off'}, the data file says "
                     f"{'on' if known['ha_enabled'] == 'yes' else 'off'}")
    peer_serial = fw.ha['peer'].get('serial') if fw.ha['enabled'] else None
    if known.get('ha_peer_serial') and peer_serial and known['ha_peer_serial'] != peer_serial:
        notes.append(f"HA peer serial number is {peer_serial}, the data file says {known['ha_peer_serial']}")
    return notes


def drop_duplicates(firewalls):
    """A firewall reached twice (two lines - e.g. a public and a private IP - leading to the same serial
    number) keeps only its first session, so no action runs on it twice."""
    first = {}
    for fw in firewalls:
        if not fw.authenticated or not fw.serial:
            continue
        if fw.serial in first:
            original = first[fw.serial]
            fw.forget_key()
            fw.auth_result = SKIPPED
            fw.auth_reason = (f"same firewall as {unit_text(original)} (serial {fw.serial}) - listed twice; "
                              f"only #{original.number} is used")
        else:
            first[fw.serial] = fw


def correlate_ha(firewalls):
    """Match each HA firewall to its peer in the list (fw.peer). Returns {fw: [notes]} for pairing
    problems: a peer that names a different unit as its own peer, or both units in the same state."""
    for fw in firewalls:
        fw.peer = None
    for fw in firewalls:
        if fw.authenticated and fw.ha and fw.ha['enabled']:
            fw.peer = find_peer(fw, firewalls, need_ha=False)
    notes = {}
    for fw in firewalls:
        other = fw.peer
        if not other or not (other.authenticated and other.ha and other.ha['enabled']):
            continue
        if other.peer is not fw:
            if other.peer:
                named = unit_text(other.peer)
            else:
                named = other.ha['peer'].get('mgmt_ip') or other.ha['peer'].get('serial') or 'no peer'
            notes.setdefault(fw, []).append(f"its HA peer {unit_text(other)} names {named} as its peer instead")
            continue
        state, peer_state = fw.ha['local'].get('state'), other.ha['local'].get('state')
        if state and state == peer_state and state in ('active', 'passive'):
            notes.setdefault(fw, []).append(f"both units of the HA pair report {state_text(state)}")
    return notes


def peer_text(fw):
    """The HA Peer column: the peer's # and hostname when it's in the list, else its management IP."""
    if not fw.authenticated or not fw.ha or not fw.ha['enabled']:
        return '-'
    if fw.peer:
        return unit_text(fw.peer) + ('' if fw.peer.authenticated else ' (not authenticated)')
    peer = fw.ha['peer']
    address = peer.get('mgmt_ip') or peer.get('serial') or 'unknown'
    # Not in this session's list, but the device database may know it by its serial number
    known = DEVICES.devices.get(peer.get('serial'), {})
    if known.get('hostname'):
        return f"{known['hostname']} ({address}, not in list)"
    return f"{address} (not in list)"


def record_devices(firewalls):
    """Store every authenticated firewall in the device database, by serial number - twice, so each
    peer's hostname is filled in whichever unit was recorded first."""
    for _ in range(2):
        for fw in firewalls:
            if fw.authenticated:
                DEVICES.record(fw)


def review_inventory(firewalls):
    """After authentication: drop duplicate sessions, check each firewall's reported details against
    the target list, pair up HA units, and show the result for the whole list."""
    for fw in firewalls:
        fw.notes = []
    drop_duplicates(firewalls)
    for fw in firewalls:
        if fw.authenticated:
            note = hostname_note(fw)
            fw.notes += ([note] if note else []) + known_data_notes(fw)
    for fw, notes in correlate_ha(firewalls).items():
        fw.notes += notes
    record_devices(firewalls)

    print()
    print_table([{
        '#': str(fw.number),
        'Firewall': fw.name,
        'Hostname': fw.hostname or (f"{fw.expected_hostname} (list)" if fw.expected_hostname else '-'),
        'Model': fw.model or '-',
        'PAN-OS': fw.sw_version or '-',
        'HA': ha_label(fw) if fw.authenticated else '-',
        'HA Peer': peer_text(fw),
        'Result': fw.auth_result or '-',
        'Notes': '; '.join(fw.notes) if fw.auth_result == PASS and fw.authenticated else fw.auth_reason,
    } for fw in firewalls])
    counts = {result: sum(fw.auth_result == result for fw in firewalls) for result in (PASS, FAIL, SKIPPED)}
    print(f"\nAuthentication: {counts[PASS]} passed, {counts[FAIL]} failed"
          + (f", {counts[SKIPPED]} skipped" if counts[SKIPPED] else ''))
    pairs = {frozenset((fw, fw.peer)) for fw in firewalls if fw.peer}
    unpaired = [fw for fw in firewalls if fw.authenticated and fw.ha and fw.ha['enabled'] and not fw.peer]
    if pairs or unpaired:
        print(f"HA: {len(pairs)} pair(s) in the list"
              + (f"; peer not in the list for {', '.join(f'#{fw.number}' for fw in unpaired)}" if unpaired else ''))
    flagged = [fw for fw in firewalls if fw.notes and fw.authenticated]
    if flagged:
        print("\nCheck these firewalls:")
        for fw in flagged:
            for note in fw.notes:
                print(f"  {fw}: {note}")


# ---------------------------------------------------------------- versions

def field(info, name):
    value = (info.findtext(name) or '').strip()
    return '-' if value in NOT_INSTALLED else value


def apps_and_threats(info):
    """One value for the Apps & Threats package. The two versions match unless only Apps is installed."""
    apps, threats = field(info, 'app-version'), field(info, 'threat-version')
    if apps == '-' or threats == apps:
        return apps
    if threats == '-':
        return f"{apps} (apps only)"
    return f"{apps} / {threats}"


def read_system_info(firewalls):
    """show system info from each firewall, reporting (and leaving out) any that fail."""
    infos = []
    for fw in firewalls:
        try:
            infos.append((fw, fw.system_info()))
        except (PanError, requests.RequestException) as e:
            print(f"{fw}: could not read system info: {connection_error_text(e)}")
    return infos


def show_content_versions(firewalls):
    """One row per firewall, plus a second row of release dates under the versions."""
    stage('Installed content versions')
    rows, dates = [], []
    for fw, info in read_system_info(firewalls):
        row = {**ident(fw)}
        date = {'Firewall': '  released'}
        for name, label in SYSTEM_FIELDS.items():
            row[label] = field(info, name)
        for label, (version_field, date_field) in VERSION_FIELDS.items():
            row[label] = apps_and_threats(info) if label == 'Apps & Threats' else field(info, version_field)
            if date_field and row[label] != '-':
                date[label] = short_date(info.findtext(date_field))
        rows.append(row)
        dates.append(date)
    if rows:
        print_table(rows, dates)
    else:
        print("No firewall returned its versions.")
    print_skipped(firewalls)


def show_panos_versions(firewalls):
    stage('Installed PAN-OS versions')
    rows = []
    for fw, info in read_system_info(firewalls):
        version = field(info, 'sw-version')
        try:
            released = short_date(fw.panos_release_date(version))
        except (PanError, requests.RequestException):
            released = '-'
        rows.append({
            **ident(fw),
            **{label: field(info, name) for name, label in SYSTEM_FIELDS.items()},
            'PAN-OS': version,
            'Released': released,
            'Uptime': field(info, 'uptime'),
        })
    if rows:
        print_table(rows)
        if any(row['Released'] == '-' for row in rows):
            print("\nA release date shows once a PAN-OS update check (Manage PAN-OS Updates > "
                  "Check for Updates) has been run on that firewall.")
    else:
        print("No firewall returned its versions.")
    print_skipped(firewalls)


# ---------------------------------------------------------------- update checks

def check_failure(fw, error):
    if isinstance(error, requests.ReadTimeout):
        return f"Check failed: no reply within {fw.check_timeout[1]}s"
    return f"Check failed: {connection_error_text(error)}"


def content_update_row(fw, releases, info_version):
    """Installed and newest release of one content type on one firewall, and how far behind it is."""
    current = next((r for r in releases if r.get('current') == 'yes'), None)
    installed = current['version'] if current else info_version
    latest = releases[0] if releases else None
    if not latest:
        status = 'No releases listed'
    elif installed == '-':
        status = 'Not installed'
    else:
        newer = sum(version_key(r['version']) > version_key(installed) for r in releases)
        status = 'Up to date' if not newer else f"Update available ({newer} newer)"
    row = {
        **ident(fw),
        'Installed': installed,
        'Latest': latest['version'] if latest else '-',
        'Downloaded': latest.get('downloaded', '-') if latest else '-',
        'Status': status,
    }
    date = {
        'Firewall': '  released',
        'Installed': short_date(current.get('released-on')) if current else '-',
        'Latest': short_date(latest.get('released-on')) if latest else '-',
    }
    return row, date


def check_content_updates(firewalls):
    """Ask which content to check and on which firewalls, then show installed vs available per content type.

    Returns (firewalls, content types) that were checked, for the install options, or None.
    """
    print()
    labels = list(CONTENT_TYPES)
    for number, label in enumerate(labels, 1):
        print(f"  {number}) {label}")
    contents = pick('Check for', dict(enumerate(labels, 1)))
    selected = select_firewalls('On firewalls', firewalls)
    if not contents or not selected:
        return None
    infos = dict(read_system_info(selected))

    for content in contents:
        stage(f"Available updates: {content}")
        rows, dates = [], []
        for fw in selected:
            info = infos.get(fw, ET.Element('system'))
            info_version = (apps_and_threats(info) if content == 'Apps & Threats'
                            else field(info, CONTENT_TYPES[content][1]))
            print(f"{fw}: checking with Palo Alto (up to {fw.check_timeout[1]}s)...")
            try:
                releases = fw.check_updates(content)
            except (PanError, requests.RequestException) as e:
                # An older release list would be out of date, so nothing gets installed from it
                fw.updates.pop(content, None)
                rows.append({**ident(fw), 'Installed': info_version,
                             'Latest': '-', 'Downloaded': '-', 'Status': check_failure(fw, e)})
                dates.append({})
                continue
            row, date = content_update_row(fw, releases, info_version)
            rows.append(row)
            dates.append(date)
        print()
        skipped = skipped_rows(selected, 'Status')
        print_table(rows + skipped, dates + [{} for _ in skipped])
    return selected, contents


# ---------------------------------------------------------------- jobs

def message_text(element):
    return ' '.join(''.join(element.itertext()).split()) if element is not None else ''


def merge_duplicates(releases):
    """One entry per version. A firewall can list a PAN-OS version more than once; the entry kept
    is downloaded, current or previous if any of its listings is, so each version is acted on once."""
    merged = {}
    for release in releases:
        kept = merged.get(release['version'])
        if kept is None:
            merged[release['version']] = dict(release)
            continue
        for flag in ('downloaded', 'current', 'previous'):
            if release.get(flag) == 'yes':
                kept[flag] = 'yes'
    return list(merged.values())


def disk_mb(text):
    """'8.4G' -> 8601.6, '413M' -> 413, '80K' -> 0.08; None if it isn't a df size."""
    match = DISK_SIZE.match(text)
    if not match:
        return None
    power = 'KMGTPE'.find(match[2].upper()) if match[2] else -1
    return float(match[1].replace(',', '.')) * 1024 ** power / 1024


def parse_disk_space(text):
    """{mount point: {'used': MB, 'free': MB}} from df -h output. Works when df wraps a long device
    name onto a line of its own: each row is found by its Use% column, with Used and Avail before it
    and the mount after."""
    tokens = text.split()
    disks = {}
    for i, token in enumerate(tokens[2:-1], 2):
        if token.endswith('%') and tokens[i + 1].startswith('/'):
            used, free = disk_mb(tokens[i - 2]), disk_mb(tokens[i - 1])
            if used is not None and free is not None:
                disks[tokens[i + 1]] = {'used': used, 'free': free}
    return disks


def disk_for(path, disks):
    """(mount point, {'used', 'free'}) of the filesystem holding path - its own mount, or the
    nearest parent mount if it isn't mounted separately. (None, None) if none is listed."""
    mounts = [m for m in disks if path == m or path.startswith(m.rstrip('/') + '/')]
    if not mounts:
        return None, None
    mount = max(mounts, key=len)
    return mount, disks[mount]


def disk_needs(sizes, disks):
    """What downloading images of these sizes (MB) one after another needs on each filesystem:
    {mount: MB}. Each image lands in /opt/pancfg, then moves to /opt/panrepo before the next one
    starts - so pancfg needs room for the largest, panrepo for them all. On one shared filesystem
    that's the total. Raises LookupError if a path's filesystem isn't listed."""
    mounts = {}
    for path in (PANCFG, PANREPO):
        mounts[path], _ = disk_for(path, disks)
        if mounts[path] is None:
            raise LookupError(f"couldn't find the filesystem holding {path} in show system disk-space")
    if mounts[PANCFG] == mounts[PANREPO]:
        return {mounts[PANREPO]: sum(sizes)}
    return {mounts[PANCFG]: max(sizes, default=0), mounts[PANREPO]: sum(sizes)}


def image_mb(release):
    """An image's size in MB from its release-list entry, or UNKNOWN_IMAGE_MB if it doesn't say."""
    kb = release.get('size-kb', '')
    if kb.isdigit():
        return int(kb) / 1024
    try:
        return float(release.get('size') or UNKNOWN_IMAGE_MB)
    except ValueError:
        return UNKNOWN_IMAGE_MB


def parallel(function, firewalls):
    """function(fw) for each firewall, PRECHECK_PARALLEL at a time - for read-only checks. Returns
    {fw: result, or the exception it raised}, in the order given."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=PRECHECK_PARALLEL) as pool:
        futures = {fw: pool.submit(function, fw) for fw in firewalls}
    results = {}
    for fw, future in futures.items():
        try:
            results[fw] = future.result()
        except Exception as e:
            results[fw] = e
    return results


def jobs_text(jobs):
    """'job 27488 (Downld) still running' - why a firewall with jobs queued or running is skipped."""
    parts = [f"{job_id} ({job_type}, {JOB_BUSY_STATUSES[status]})" for job_id, job_type, status in jobs[:3]]
    more = f" and {len(jobs) - 3} more" if len(jobs) > 3 else ''
    return f"{'job' if len(jobs) == 1 else 'jobs'} {', '.join(parts)}{more} not finished"


def busy_check_text(fw, outcome):
    """Why fw is skipped, from its running_jobs() outcome (a job list, or the exception raised), or
    None if nothing is running on it."""
    if isinstance(outcome, requests.ReadTimeout):
        return f"not responding - no reply within {fw.timeout[1]}s to the running-jobs check"
    if isinstance(outcome, Exception):
        return f"could not check for running jobs: {connection_error_text(outcome)}"
    return jobs_text(outcome) if outcome else None


def check_busy(firewalls):
    """{fw: reason} for the firewalls that have a job queued or running, or that couldn't be checked.
    Nothing that changes a firewall is started on these."""
    if not firewalls:
        return {}
    print(f"Checking {len(firewalls)} firewall(s) for jobs already running...")
    busy = {}
    for fw, outcome in parallel(lambda fw: fw.running_jobs(), firewalls).items():
        reason = busy_check_text(fw, outcome)
        if reason:
            busy[fw] = reason
    return busy


def set_action(rows, fw, text):
    """Set the Action column of fw's row(s) in a plan table."""
    for row in rows:
        if row.get('#') == str(fw.number):
            row['Action'] = text


def queue_timeout_of(firewalls):
    """The queue timeout for a run: the shortest of its firewalls' (they all share the config)."""
    return min((fw.queue_timeout for fw in firewalls), default=0)


def exclude_busy(rows, plans):
    """Check the plan's firewalls for running jobs. One that can't be checked is left out of plans;
    one with a job queued or running waits in the queue (if queue_timeout allows - otherwise it's
    left out too). Their rows are marked. Returns (when the check was made, {fw: reason} queued),
    for run_jobs."""
    queue_timeout = queue_timeout_of(plans)
    queued = {}
    for fw, outcome in parallel(lambda fw: fw.running_jobs(), list(plans)).items():
        reason = busy_check_text(fw, outcome)
        if not reason:
            continue
        if isinstance(outcome, Exception) or not queue_timeout:
            del plans[fw]
            set_action(rows, fw, f"Skip - {reason}")
        else:
            queued[fw] = reason
            action = next((r.get('Action', '') for r in rows if r.get('#') == str(fw.number)), '')
            set_action(rows, fw, f"Queue - wait for {reason.replace(' not finished', '')} to finish, then: {action}")
    return time.monotonic(), queued


def explain_failure(reason):
    """(kind, text) for a failed step. kind is 'corrupt' when the firewall's own checks rejected
    the image it stored, 'management' when its management plane stopped answering, else None."""
    if IMAGE_CORRUPT.search(reason):
        return 'corrupt', f"image corrupted on the firewall's disk - check its storage, don't retry. Firewall said: {reason}"
    if MANAGEMENT_LOST.search(reason):
        return 'management', f"the firewall's management stopped responding - check it before retrying ({reason})"
    return None, reason


def recover_job(fw):
    """After a download or install request got no reply: the newest job queued or running on the
    firewall - most likely the one the request started, since nothing was running when it was
    sent. None if there's none, or the firewall doesn't answer."""
    try:
        jobs = fw.running_jobs()
    except (PanError, requests.RequestException):
        return None
    return jobs[0][0] if jobs and jobs[0][0] else None


def write_results(action, rows, firewalls=()):
    """Save a results table as CSV next to the run log (<log name>_<HHMMSS>_<action>.csv), with
    each firewall's hostname and HA state, for records or a support case."""
    if not LOG or not rows:
        return
    import csv
    by_number = {str(fw.number): fw for fw in firewalls}
    for fw in getattr(firewalls, 'skipped', []):
        by_number[str(fw.number)] = fw
    slug = re.sub(r'[^a-z0-9]+', '-', action.lower()).strip('-')
    stamp = f"{datetime.datetime.now():%H%M%S}"
    path = LOG.path.with_name(f"{LOG.path.stem}_{stamp}_{slug}.csv")
    number = 1
    while path.exists():
        number += 1
        path = LOG.path.with_name(f"{LOG.path.stem}_{stamp}_{slug}-{number}.csv")
    columns = ['Time', '#', 'Firewall', 'Hostname', 'HA', 'HA Peer']
    for row in rows:
        columns += [c for c in row if c not in columns]
    now = f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}"
    try:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, columns, restval='')
            writer.writeheader()
            for row in rows:
                fw = by_number.get(row.get('#'))
                writer.writerow({'Time': now, 'Hostname': (fw.hostname or fw.expected_hostname or '') if fw else '',
                                 'HA': ha_label(fw) if fw else '', 'HA Peer': peer_text(fw) if fw else '', **row})
    except OSError as e:
        print(f"Could not save the results to {path}: {e.strerror}")
        return
    print(f"Results saved to {path}")


def start_job(fw, cmd):
    """Send a download or install request. Returns its job ID, or None if the firewall finished it straight away."""
    result = fw.op(cmd)
    job = result.findtext('job') if result is not None else None
    if not job:
        match = re.search(r'jobid (\d+)', message_text(result))
        job = match[1] if match else None
    return job.strip() if job else None


def job_state(fw, job):
    """(status, result, progress, details) of one job. Status is PEND, ACT or FIN; result is OK or FAIL once finished."""
    element = fw.op(f"<show><jobs><id>{job}</id></jobs></show>").find('job')
    if element is None:
        raise PanError(f"show jobs returned nothing for job {job}")
    return (element.findtext('status') or '', element.findtext('result') or '',
            (element.findtext('progress') or '').strip(), message_text(element.find('details')))


def run_jobs(plans, limit=0, after=None, prior=None, stop_after=0, busy_checked=None, queued=None,
             queue_timeout=0):
    """Run each firewall's steps in order, firewalls side by side, and wait for every job to finish.

    plans maps a firewall to a list of (description, command). A failed step stops the rest of that
    firewall's steps. Returns {firewall: (result, detail)}. Ctrl+C stops watching; jobs already
    started keep running on the firewalls.

    - limit: at most this many firewalls working at once (0 = no limit); the rest wait their turn.
    - after: {fw: other} - fw doesn't start until other has finished (DONE), here or in prior
      (outcomes of an earlier run); if other didn't finish, fw is skipped. Used to keep an HA
      pair's units from working at the same time.
    - stop_after: once this many firewalls have failed in a way that points at the firewall (a
      corrupt image, or its management stopping - see explain_failure), no more firewalls are
      started; those already working are still watched. The rest come back as NOT_STARTED.
    - busy_checked: when the plan's firewalls were checked for running jobs. A firewall's first
      step is checked again if that was more than BUSY_RECHECK seconds ago; every later step is
      always checked again - so a job that started between two steps (e.g. after the base image)
      is caught too.
    - queued: {fw: reason} - firewalls in the plan that had a job running at that check. They wait
      in the queue instead of starting.
    - queue_timeout: seconds a firewall waits in the queue - checked every BUSY_RECHECK seconds -
      for its jobs to finish before it's skipped. 0 skips a busy firewall straight away.
    Nothing is ever sent to a firewall while it has a job queued or running, or can't be checked.
    A request that gets no reply might still have started a job: the firewall's newest running job
    is watched instead, or the firewall is reported as UNKNOWN.
    """
    pending = {fw: list(steps) for fw, steps in plans.items()}
    after, prior = after or {}, prior or {}
    running, outcomes, started = {}, {}, set()
    serious = 0
    # Firewalls waiting for their jobs to finish: {fw: {'since', 'next', 'reason'}}; and when each
    # firewall was last seen with nothing running
    waiting, idle_at = {}, {}
    for fw, reason in (queued or {}).items():
        if fw in pending:
            if queue_timeout:
                now = time.monotonic()
                waiting[fw] = {'since': now, 'next': (busy_checked or now) + BUSY_RECHECK, 'reason': reason}
                print(f"{fw}: queued - {reason}. Waiting up to {queue_timeout // 60} min for it to finish.")
            else:
                pending.pop(fw)
                outcomes[fw] = (SKIPPED, f"not started - {reason}")

    def count_serious():
        nonlocal serious
        serious += 1
        if stop_after and serious == stop_after:
            print(f"\n{serious} firewall(s) have failed with a corrupt image, stopped responding, or not "
                  f"answered - no more firewalls will be started. The ones already working are still watched.\n")

    def fail(fw, label, reason):
        kind, text = explain_failure(reason)
        pending.pop(fw, None)
        running.pop(fw, None)
        outcomes[fw] = (FAILED, f"{label}: {text}")
        print(f"{fw}: FAILED - {label}: {text}")
        if kind:
            count_serious()

    def end(fw, result, detail):
        pending.pop(fw, None)
        waiting.pop(fw, None)
        outcomes[fw] = (result, detail)
        print(f"{fw}: {result} - {detail}")

    def clear_to_send(fw):
        """Whether fw has nothing running, so its next step can be sent. A busy firewall waits in
        the queue (rechecked every BUSY_RECHECK seconds) until queue_timeout, then is skipped."""
        now = time.monotonic()
        wait = waiting.get(fw)
        if wait:
            if now < wait['next']:
                return False
        elif busy_checked is None:
            return True
        elif fw not in started and now - idle_at.get(fw, busy_checked) <= BUSY_RECHECK:
            # First step, and the pre-check was moments ago. Every later step is checked afresh: a
            # job may have started while the previous step ran.
            return True
        reason = busy_now(fw)
        if reason is None:
            if wait:
                waited = (now - wait['since']) / 60
                print(f"{fw}: nothing running now (waited {waited:.0f} min) - starting")
                del waiting[fw]
            idle_at[fw] = now
            return True
        step = pending[fw][0][0] if pending.get(fw) else 'next step'
        if not wait:
            if not queue_timeout:
                end(fw, SKIPPED, f"not started - {reason}" if fw not in started
                    else f"{step} not sent - {reason}")
                return False
            waiting[fw] = wait = {'since': now, 'reason': reason}
            print(f"{fw}: queued - {reason}. Waiting up to {queue_timeout // 60} min for it to finish.")
        elif now - wait['since'] > queue_timeout:
            end(fw, SKIPPED, f"{'not started' if fw not in started else step + ' not sent'} - still "
                             f"busy after waiting {queue_timeout // 60} min: {reason}")
            return False
        wait['next'], wait['reason'] = now + BUSY_RECHECK, reason
        return False

    def may_start(fw):
        """Whether a firewall that hasn't started yet can start now. Skips it if it can't ever."""
        if stop_after and serious >= stop_after:
            waiting.pop(fw, None)
            return False
        other = after.get(fw)
        if other is not None:
            state = outcomes.get(other) or prior.get(other)
            if state is None:
                if other in pending or other in running:
                    return False
            elif state[0] != DONE:
                end(fw, SKIPPED, f"not started - its HA peer {other} didn't finish ({state[0]})")
                return False
        working = sum(1 for f in started if f in pending or f in running)
        if limit and working >= limit:
            return False
        return True

    try:
        while pending or running:
            progressed = False
            for fw in list(pending):
                if fw in running or fw not in pending:
                    continue
                if not pending[fw]:
                    del pending[fw]
                    outcomes[fw] = (DONE, 'All steps finished')
                    progressed = True
                    continue
                if fw not in started and not may_start(fw):
                    progressed = progressed or fw not in pending
                    continue
                if not clear_to_send(fw):
                    progressed = progressed or fw not in pending
                    continue
                started.add(fw)
                progressed = True
                label, cmd = pending[fw].pop(0)
                try:
                    job = start_job(fw, cmd)
                except requests.ReadTimeout:
                    job = recover_job(fw)
                    if job is None:
                        end(fw, UNKNOWN, f"{label}: no reply within {fw.timeout[1]}s - it may be running on "
                                         f"the firewall, not watched. Check its task list before trying again")
                        count_serious()
                        continue
                    print(f"{fw}: {label} - no reply to the request, but job {job} is running on the "
                          f"firewall - watching it")
                except (PanError, requests.RequestException) as e:
                    fail(fw, label, connection_error_text(e))
                    continue
                else:
                    if job is None:
                        print(f"{fw}: {label} - done")
                        continue
                    print(f"{fw}: {label} - job {job} started")
                running[fw] = {'label': label, 'id': job, 'started': time.monotonic(),
                               'failures': 0, 'progress': ''}
            if not running:
                if waiting:
                    # Only queued firewalls left: sleep until the next one is due a check
                    time.sleep(max(1, min(w['next'] for w in waiting.values()) - time.monotonic()))
                    continue
                if pending and not progressed:
                    break   # nothing left can start: stopped after failures
                continue

            time.sleep(min(fw.poll_interval for fw in running))
            for fw, job in list(running.items()):
                try:
                    status, result, progress, details = job_state(fw, job['id'])
                except (PanError, requests.RequestException) as e:
                    if not fw.authenticated:
                        # The job carries on without the session; only the watching stops
                        fail(fw, job['label'], f"the firewall ended the session ({e}). Job {job['id']} "
                                               f"may still finish - use Retry authentication, then check")
                        continue
                    # The management plane can be briefly busy during an install; give it a few tries
                    job['failures'] += 1
                    if job['failures'] >= JOB_POLL_FAILURES:
                        fail(fw, job['label'], f"lost track of job {job['id']} ({connection_error_text(e)})")
                    continue
                job['failures'] = 0
                if status == 'FIN':
                    del running[fw]
                    if result == 'OK':
                        print(f"{fw}: {job['label']} - done")
                    else:
                        fail(fw, job['label'], details or result or 'job failed')
                elif time.monotonic() - job['started'] > fw.job_timeout:
                    fail(fw, job['label'], f"job {job['id']} still running after {fw.job_timeout}s - "
                                           f"check the firewall's task list")
                elif progress.isdigit() and progress != job['progress']:
                    job['progress'] = progress
                    print(f"{fw}: {job['label']} - {progress}%")
    except KeyboardInterrupt:
        print("\nStopped watching. Jobs already started keep running on the firewalls; "
              "steps that hadn't started were not sent.")
        for fw, job in running.items():
            outcomes[fw] = (STOPPED, f"{job['label']}: job {job['id']} still running, not watched")
        for fw in pending:
            outcomes.setdefault(fw, (STOPPED, 'Remaining steps not sent'))
        return outcomes
    for fw in pending:
        outcomes[fw] = (NOT_STARTED, f"not started - stopped after {serious} failure(s)")
    return outcomes


def run_plan(rows, plans, action, firewalls=()):
    """Show what will happen on each firewall, confirm, run the jobs and show the results.
    firewalls is the Selection the plan was made for, so skipped firewalls are listed too.

    Firewalls with a job already queued or running are left out. Returns True if anything was
    sent to a firewall.
    """
    print()
    if plans:
        print(f"Checking {len(plans)} firewall(s) for jobs already running...")
    checked, queued = exclude_busy(rows, plans)
    print_table(rows + skipped_rows(firewalls, 'Action'))
    if not plans:
        print(f"\nNothing to {action.lower()}.")
        return False
    queue_timeout = queue_timeout_of(plans)
    if queued:
        print(f"\n{len(queued)} firewall(s) have a job running: each waits up to {queue_timeout // 60} min "
              f"for it to finish before anything is sent.")
    print()
    if not confirm(f"{action} on {len(plans)} firewall(s)?"):
        print("Nothing sent.")
        return False
    stage(action)
    outcomes = run_jobs(plans, busy_checked=checked, queued=queued, queue_timeout=queue_timeout)
    print()
    results = result_rows(outcomes, rows) + skipped_rows(firewalls, 'Result')
    print_table(results)
    write_results(action, results, firewalls)
    return True


def result_rows(outcomes, rows=()):
    """The results table: one row per firewall that ran, then one per firewall the plan table
    skipped (rows with an Action starting 'Skip'), in firewall order."""
    results = {str(fw.number): {**ident(fw), 'Result': result, 'Detail': detail}
               for fw, (result, detail) in outcomes.items()}
    for row in rows:
        if row.get('Action', '').startswith('Skip') and row['#'] not in results:
            results[row['#']] = {**{k: row[k] for k in ('#', 'Firewall', 'Hostname') if k in row}, 'Result': SKIPPED,
                                 'Detail': row['Action'][len('Skip - '):] if row['Action'].startswith('Skip - ')
                                 else row['Action']}
    return sorted(results.values(), key=lambda row: int(row['#']))


def merge_releases(releases_by_fw):
    """One list of every release the firewalls listed, newest first, counting how many list,
    have downloaded and have installed each. Returns [(version, summary)]."""
    merged = {}
    for releases in releases_by_fw.values():
        for release in releases:
            summary = merged.setdefault(release['version'], {
                'release': release, 'listed': 0, 'downloaded': 0, 'installed': 0})
            summary['listed'] += 1
            summary['downloaded'] += release.get('downloaded') == 'yes'
            summary['installed'] += release.get('current') == 'yes'
    return sorted(merged.items(), key=lambda item: version_key(item[0]), reverse=True)


def release_rows(numbered, total):
    return [{
        '#': str(number),
        'Version': version,
        'Released': short_date(summary['release'].get('released-on')),
        'Size': size_text(summary['release']),
        'Listed on': f"{summary['listed']} of {total}",
        'Downloaded on': str(summary['downloaded']),
        'Installed on': str(summary['installed']),
    } for number, (version, summary) in numbered.items()]


def current_release(releases):
    return next((r for r in releases or [] if r.get('current') == 'yes'), None)


# ---------------------------------------------------------------- content installs

def content_steps(content, release, latest=False, disable_new_apps=False):
    """Download (unless already downloaded) and install steps for one content release.

    latest uses the 'latest' keyword, as Palo Alto's API docs do for installing the newest
    release; otherwise the release is named. GP Client packages are downloaded and activated by version.
    disable_new_apps sets 'Disable new apps in content update' on an Apps & Threats install.
    """
    outer, inner = CONTENT_TYPES[content][0]
    version = release['version']
    options = DISABLE_NEW_APPS if content == 'Apps & Threats' and disable_new_apps else ''
    if content == 'GP Client':
        download = f"<download><version>{version}</version></download>"
        install = f"<activate><version>{version}</version></activate>"
    elif latest:
        download = '<download><latest></latest></download>'
        install = f"<install>{options}<version>latest</version></install>"
    else:
        download = f"<download><file>{release.get('filename', '')}</file></download>"
        install = f"<install>{options}<version>{version}</version></install>"
    steps = []
    if release.get('downloaded') != 'yes':
        steps.append((f"download {content} {version}",
                      f"<request><{outer}><{inner}>{download}</{inner}></{outer}></request>"))
    label = f"install {content} {version}"
    if content == 'Apps & Threats':
        label += f" ({new_apps_text(disable_new_apps)})"
    steps.append((label, f"<request><{outer}><{inner}>{install}</{inner}></{outer}></request>"))
    return steps


def step_text(release):
    return 'Download + install' if release.get('downloaded') != 'yes' else 'Install (already downloaded)'


def new_apps_text(disable_new_apps):
    return 'new apps disabled' if disable_new_apps else 'new apps enabled'


def ask_new_apps():
    """How to install Apps & Threats: True to disable the new App-IDs in the update, False to
    enable them, None to cancel. No default, so it's always a deliberate choice."""
    print("\nApps & Threats - new App-IDs in this update:")
    print("  1) Disable new apps in content update (they stay disabled until reviewed and enabled)")
    print("  2) Enable new apps (they start matching traffic as soon as the install finishes)")
    chosen = pick('New apps', {1: True, 2: False}, single=True)
    return chosen[0] if chosen else None


def install_current(firewalls, contents):
    """Install the newest release of each checked content type on every checked firewall that's behind.

    Content types go in dependency order (Antivirus needs a recent Apps & Threats), and a
    failure stops that firewall's later steps.
    """
    stage('Install Current Version')
    rows, candidates = [], []
    for content in (c for c in CONTENT_TYPES if c in contents):
        for fw in firewalls:
            releases = fw.updates.get(content)
            current = current_release(releases)
            row = {'Content': content, **ident(fw),
                   'Installed': current['version'] if current else '-', 'Install': '-'}
            if not releases:
                row['Action'] = 'Skip - update check failed'
            elif releases[0].get('current') == 'yes':
                row['Action'] = 'Skip - up to date'
            else:
                candidates.append((content, fw, row, releases[0]))
                row['Install'] = releases[0]['version']
                row['Action'] = step_text(releases[0])
            rows.append(row)

    # Choose which of the content types with an update to install
    pending = list(dict.fromkeys(content for content, *_ in candidates))
    if len(pending) > 1:
        print()
        print_table(rows)
        print()
        for number, content in enumerate(pending, 1):
            count = sum(c == content for c, *_ in candidates)
            print(f"  {number}) {content} ({count} firewall(s))")
        chosen = pick('Install', dict(enumerate(pending, 1)), blank_means_all=False)
        if not chosen:
            print("Nothing installed.")
            return False
        for content, _, row, _ in candidates:
            if content not in chosen:
                row['Install'], row['Action'] = '-', 'Skip - not selected'
        candidates = [candidate for candidate in candidates if candidate[0] in chosen]

    disable_new_apps = False
    if any(content == 'Apps & Threats' for content, *_ in candidates):
        disable_new_apps = ask_new_apps()
        if disable_new_apps is None:
            print("Nothing installed.")
            return False

    plans = {}
    for content, fw, row, release in candidates:
        plans.setdefault(fw, []).extend(content_steps(content, release, True, disable_new_apps))
        if content == 'Apps & Threats':
            row['Action'] += f" - {new_apps_text(disable_new_apps)}"
    return run_plan(rows, plans, 'Install', firewalls)


def advanced_install(firewalls, contents):
    """Pick one content type and one version from the merged release lists, and install it on every checked firewall."""
    stage('Advanced Installation')
    if len(contents) > 1:
        for number, content in enumerate(contents, 1):
            print(f"  {number}) {content}")
        chosen = pick('Content', dict(enumerate(contents, 1)), single=True)
        if not chosen:
            return False
        content = chosen[0]
    else:
        content = contents[0]

    releases_by_fw = {fw: fw.updates[content] for fw in firewalls if fw.updates.get(content)}
    versions = dict(enumerate(merge_releases(releases_by_fw), 1))
    if not versions:
        print(f"No {content} releases listed - run Check for Updates again.")
        return False
    print(f"\n{content} releases listed by the checked firewalls:")
    print_table(release_rows(versions, len(firewalls)))
    print()
    chosen = pick('Install version', versions, single=True)
    if not chosen:
        return False
    version = chosen[0][0]

    disable_new_apps = False
    if content == 'Apps & Threats':
        disable_new_apps = ask_new_apps()
        if disable_new_apps is None:
            print("Nothing installed.")
            return False

    rows, plans = [], {}
    for fw in firewalls:
        releases = fw.updates.get(content)
        current = current_release(releases)
        release = next((r for r in releases or [] if r['version'] == version), None)
        row = {**ident(fw), 'Installed': current['version'] if current else '-'}
        if not releases:
            row['Action'] = 'Skip - update check failed'
        elif not release:
            row['Action'] = 'Skip - this firewall does not list that version'
        elif release.get('current') == 'yes':
            row['Action'] = 'Skip - already installed'
        elif (content != 'GP Client' and release.get('downloaded') != 'yes'
              and not release.get('filename')):
            row['Action'] = "Skip - the firewall didn't list a file name to download"
        else:
            plans[fw] = content_steps(content, release, disable_new_apps=disable_new_apps)
            older = current and version_key(version) < version_key(current['version'])
            row['Action'] = step_text(release) + (' - older than installed' if older else '')
            if content == 'Apps & Threats':
                row['Action'] += f" - {new_apps_text(disable_new_apps)}"
        rows.append(row)
    print(f"\nInstall {content} {version}:")
    return run_plan(rows, plans, 'Install', firewalls)


def manage_content_updates(firewalls):
    """Check for Updates first; the install options use that check's firewalls and release lists."""
    checked = None
    while True:
        choice = menu('Manage Content Updates', [
            'Check for Updates',
            'Install Current Version' if checked else None,
            'Advanced Installation' if checked else None,
            'Clear Old Content Cache',
            'Delete Downloaded Content (Apps & Threats) Images',
        ])
        if choice == '1':
            checked = check_content_updates(firewalls) or checked
        elif choice in ('2', '3'):
            installed = (install_current if choice == '2' else advanced_install)(*checked)
            if installed:
                # The release lists no longer show what's installed
                checked = None
                print("\nRun Check for Updates again to see the new versions.")
        elif choice == '4':
            clear_content_cache(firewalls)
        elif choice == '5':
            delete_downloaded(firewalls, 'Apps & Threats')
        else:
            return


# ---------------------------------------------------------------- PAN-OS updates

def check_panos_updates(firewalls):
    """Refresh each firewall's PAN-OS release list from Palo Alto, so images can be downloaded."""
    selected = select_firewalls('Check for PAN-OS updates on', firewalls)
    if not selected:
        return
    stage('Check for PAN-OS updates')
    rows = []
    for fw in selected:
        print(f"{fw}: checking with Palo Alto (up to {fw.check_timeout[1]}s)...")
        row = {**ident(fw)}
        try:
            releases = fw.check_updates(PANOS)
        except (PanError, requests.RequestException) as e:
            fw.updates.pop(PANOS, None)
            rows.append({**row, 'Installed': '-', 'Result': check_failure(fw, e)})
            continue
        current = current_release(releases)
        rows.append({**row, 'Installed': current['version'] if current else '-',
                     'Result': f"Release list updated ({len(releases)} versions)"})
    print()
    print_table(rows + skipped_rows(selected, 'Result'))


def version_matches(version, text):
    """'11.2' matches 11.2.x but not 11.20.x; '11.2.4' matches 11.2.4 and 11.2.4-h1."""
    if not version.startswith(text):
        return False
    return len(version) == len(text) or text[-1] in '.-' or version[len(text)] in '.-'


def panos_steps(version):
    return [(f"download PAN-OS {version}",
             f"<request><system><software><download><version>{version}</version></download></software></system></request>")]


def feature_of(version):
    """'11.2.10-h3' -> '11.2'."""
    return '.'.join(version.split('.')[:2])


def upgrade_path(plans, releases_by_fw, version):
    """Firewalls that would skip a feature release on the way to version: PAN-OS needs each feature
    release in between installed in turn, or its base image downloaded for a multi-version upgrade.
    Prints them, and returns {fw: [base image releases in between that aren't downloaded, oldest
    first]} for the ones that list those images."""
    target = feature_of(version)
    lines, missing_by_fw = [], {}
    for fw in plans:
        releases = releases_by_fw[fw]
        current = current_release(releases)
        if not current:
            continue
        start = feature_of(current['version'])
        between = sorted({feature_of(r['version']) for r in releases
                          if version_key(start) < version_key(feature_of(r['version'])) < version_key(target)},
                         key=version_key)
        if not between:
            continue
        by_version = {r['version']: r for r in releases}
        missing = [f"{f}.0" for f in between if by_version.get(f"{f}.0", {}).get('downloaded') != 'yes']
        unlisted = [v for v in missing if v not in by_version]
        if missing and len(unlisted) < len(missing):
            missing_by_fw[fw] = [by_version[v] for v in missing if v in by_version]
        lines.append(f"  {fw}: {start} -> {target} passes through {', '.join(between)}"
                     + (f" - base image(s) not downloaded: {', '.join(missing)}" if missing else '')
                     + (f" ({', '.join(unlisted)} not in its release list)" if unlisted else ''))
    if lines:
        print(f"\nUpgrade path: these firewalls skip feature release(s) on the way to {target}. Each feature "
              f"release in between has to be installed in turn, or its base image downloaded for a "
              f"multi-version upgrade:")
        for line in lines:
            print(line)
    return missing_by_fw


def download_panos(firewalls, config):
    """Find the release matching the version typed, and download that image to the chosen firewalls."""
    selected = select_firewalls('Download a PAN-OS image to', firewalls)
    if not selected:
        return
    stage('Download PAN-OS Image')
    releases_by_fw = {}
    for fw in selected:
        releases = fw.updates.get(PANOS)
        if releases is None:
            # Not checked in this run: use the firewall's list from its last check
            try:
                releases = fw.cached_releases(PANOS)
            except (PanError, requests.RequestException) as e:
                print(f"{fw}: could not read the release list: {connection_error_text(e)}")
                continue
        if releases:
            releases_by_fw[fw] = releases
        else:
            print(f"{fw}: no release list yet - run Check for Updates first")
    if not releases_by_fw:
        return
    merged = merge_releases(releases_by_fw)

    while True:
        text = ask("PAN-OS version, e.g. 11.2 or 11.2.4-h4 [cancel]: ").strip()
        if not text:
            return
        matches = [item for item in merged if version_matches(item[0], text)]
        if matches:
            break
        features = sorted({'.'.join(v.split('.')[:2]) for v, _ in merged}, key=version_key, reverse=True)
        print(f"  No release matches '{text}'. Feature releases listed: {', '.join(features)}")

    if len(matches) == 1:
        version = matches[0][0]
        print(f"Matched {version}.")
    else:
        numbered = dict(enumerate(matches, 1))
        print(f"\n{len(matches)} releases match '{text}':")
        print_table(release_rows(numbered, len(releases_by_fw)))
        print()
        chosen = pick('Download', numbered, single=True)
        if not chosen:
            return
        version = chosen[0][0]

    feature = '.'.join(version.split('.')[:2])
    base = f"{feature}.0"
    rows, plans, images, need_base = [], {}, {}, []
    for fw in selected:
        releases = releases_by_fw.get(fw, [])
        current = current_release(releases)
        release = next((r for r in releases if r['version'] == version), None)
        row = {**ident(fw), 'Installed': current['version'] if current else '-'}
        if not releases:
            row['Action'] = 'Skip - no release list'
        elif not release:
            row['Action'] = 'Skip - this firewall does not list that version'
        elif release.get('current') == 'yes':
            row['Action'] = 'Skip - already installed'
        elif release.get('downloaded') == 'yes':
            row['Action'] = 'Skip - already downloaded'
        else:
            # Moving to a new feature release: PAN-OS refuses to load the image until that release's
            # base image is downloaded, so the base always goes first - there's no point asking
            base_release = next((r for r in releases if r['version'] == base), None)
            needs_base = (version != base and current and not current['version'].startswith(f"{feature}.")
                          and (base_release is None or base_release.get('downloaded') != 'yes'))
            if needs_base and base_release is None:
                row['Action'] = (f"Skip - needs the {base} base image first, and this firewall doesn't list it "
                                 f"- run Check for Updates")
            else:
                images[fw] = ([base_release] if needs_base else []) + [release]
                plans[fw] = [step for r in images[fw] for step in panos_steps(r['version'])]
                if needs_base:
                    need_base.append(fw)
        rows.append(row)

    if need_base:
        print(f"\nThe {feature} base image ({base}) isn't downloaded on "
              + ', '.join(str(fw) for fw in need_base) + '.')
        print(f"PAN-OS won't load {version} without it, so it's downloaded first on those firewall(s).")
    # Feature releases skipped on the way: offer their base images too, for a multi-version upgrade
    in_between = upgrade_path(plans, releases_by_fw, version)
    if in_between and confirm("Download the missing in-between base image(s) too, before the others?"):
        for fw, extra in in_between.items():
            images[fw] = extra + images[fw]
            plans[fw] = [step for r in images[fw] for step in panos_steps(r['version'])]
    for fw in plans:
        versions = [r['version'] for r in images[fw]]
        set_action(rows, fw, f"Download {', then '.join(versions)} "
                             f"({sum(image_mb(r) for r in images[fw]):,.0f} MB)")

    # A firewall whose download already failed this session in a way that points at the firewall
    tried = [fw for fw in plans if fw.download_failure]
    if tried:
        print(f"\nA download already failed on {len(tried)} of these firewall(s) this session:")
        for fw in tried:
            print(f"  {fw}: {fw.download_failure}")
        if not confirm("Try them again?"):
            for fw in tried:
                del plans[fw]
                set_action(rows, fw, 'Skip - a download failed on it earlier this session')
    print(f"\nDownload PAN-OS {version}:")
    run_downloads(rows, plans, images, selected, config)


def check_disk(fw, sizes, disks, warn_percent):
    """(skip reason or None, warning or None, 'Disk after' text) for downloading images of these
    sizes (MB) to fw, from its show system disk-space. Skipped if any filesystem lacks the room;
    warned if any would end up over warn_percent used."""
    try:
        needs = disk_needs(sizes, disks)
    except LookupError as e:
        return str(e), None, '-'
    after, over = [], []
    for mount, need in needs.items():
        disk = disks[mount]
        total = disk['used'] + disk['free']
        percent = (disk['used'] + need) / total * 100 if total else 100
        after.append(f"{mount} {percent:.0f}%")
        if need > disk['free']:
            return (f"not enough free space on {mount} - {disk['free']:,.0f} MB free, {need:,.0f} MB needed "
                    f"for {len(sizes)} image(s)"), None, ', '.join(after)
        if percent > warn_percent:
            over.append(f"{mount} would be {percent:.0f}% used ({need:,.0f} MB of {disk['free']:,.0f} MB free)")
    return None, ('; '.join(over) or None), ', '.join(after)


def precheck_downloads(rows, plans, images, config):
    """Before a PAN-OS download, on every firewall in the plan at once: jobs queued or running, free
    space for every image it will download (check_disk), and its HA state, read again so the pair
    order is current. A firewall that doesn't answer, or lacks the space, is left out. One with a job
    running is queued (or left out if queue_timeout is 0).

    Returns (when the check was made, {fw: reason} queued, {fw: warning} for the firewalls whose
    disk use would pass disk_warn_percent)."""
    warn_percent = config['disk_warn_percent']
    print(f"Checking {len(plans)} firewall(s) before downloading: jobs already running, "
          + (f"free space in {PANCFG} and {PANREPO}, " if warn_percent else '') + "HA state...")

    def check(fw):
        jobs = fw.running_jobs()
        disks = fw.disk_space() if warn_percent else None
        try:
            fw.read_ha()
        except PanError:
            pass   # keep the state read at authentication
        return jobs, disks

    for row in rows:
        action = row.pop('Action')
        row['Disk after'] = '-'
        row['Action'] = action
    queued, warned = {}, {}
    for fw, outcome in parallel(check, list(plans)).items():
        reason = None
        if isinstance(outcome, requests.ReadTimeout):
            reason = f"not responding - no reply within {fw.timeout[1]}s to the pre-checks"
        elif isinstance(outcome, Exception):
            reason = f"pre-check failed: {connection_error_text(outcome)}"
        else:
            jobs, disks = outcome
            if warn_percent:
                reason, warning, after = check_disk(fw, [image_mb(r) for r in images[fw]], disks, warn_percent)
                for row in rows:
                    if row['#'] == str(fw.number):
                        row['Disk after'] = after
                if warning and not reason:
                    warned[fw] = warning
            if jobs and not reason:
                if fw.queue_timeout:
                    queued[fw] = jobs_text(jobs)
                    action = next(r['Action'] for r in rows if r['#'] == str(fw.number))
                    set_action(rows, fw, f"Queue - wait for {jobs_text(jobs).replace(' not finished', '')}, "
                                         f"then: {action}")
                else:
                    reason = jobs_text(jobs)
        if reason:
            del plans[fw]
            warned.pop(fw, None)
            set_action(rows, fw, f"Skip - {reason}")
    return time.monotonic(), queued, warned


def ha_order(plans):
    """The plan's firewalls in the order to start them, with each HA pair's passive unit just before
    its active one, and {active: passive}: the active unit waits until its peer has finished.
    Firewalls whose peer isn't in the plan keep their place."""
    firewalls = list(plans)
    order, after, placed = [], {}, set()
    for fw in firewalls:
        if fw in placed:
            continue
        peer = find_peer(fw, firewalls) if fw.ha and fw.ha.get('enabled') else None
        if peer is None or peer in placed:
            order.append(fw)
            placed.add(fw)
            continue
        first, second = sorted((fw, peer), key=lambda u: (u.ha['local'].get('state') in HA_ACTIVE_STATES, u.number))
        order += [first, second]
        placed.update((first, second))
        after[second] = first
    return order, after


def ask_test_group(count, default):
    """How many firewalls to download to before stopping to ask about the rest; 0 for all at once."""
    while True:
        text = prompt(f"Test group - how many firewalls to download to first, then stop and ask before "
                      f"the rest (0 = all {count} at once)", str(min(default, count))).strip()
        if text.isdigit() and int(text) <= count:
            return int(text)
        print(f"  Enter a number from 0 to {count}.")


def run_downloads(rows, plans, images, selected, config):
    """Run a PAN-OS download plan with its safeguards: pre-checks (precheck_downloads), HA pairs one
    unit at a time (passive first), at most max_parallel_downloads at once, an optional test group
    first, and a stop - with a question - after stop_after_failures serious failures."""
    print()
    checked, queued, warned = precheck_downloads(rows, plans, images, config) if plans else (None, {}, {})
    print()
    print_table(rows + skipped_rows(selected, 'Action'))
    if warned:
        print(f"\nDisk use would pass {config['disk_warn_percent']}% on {len(warned)} firewall(s):")
        for fw, warning in warned.items():
            print(f"  {fw}: {warning}")
        if not confirm("Download to these firewall(s) anyway?"):
            for fw in warned:
                del plans[fw]
                queued.pop(fw, None)
                set_action(rows, fw, f"Skip - disk use would pass {config['disk_warn_percent']}%: {warned[fw]}")
    if not plans:
        print("\nNothing to download.")
        return
    order, after = ha_order(plans)
    limit, stop_after = config['max_parallel_downloads'], config['stop_after_failures']
    queue_timeout = queue_timeout_of(plans)
    print()
    if queued:
        print(f"{len(queued)} firewall(s) have a job running: each waits up to {queue_timeout // 60} min for "
              f"it to finish, checked every {BUSY_RECHECK}s. Nothing is sent while a job runs.")
    if after:
        print(f"{len(after)} HA pair(s): the passive unit downloads first, the active unit once it has finished.")
    print(f"At most {limit} firewall(s) download at once." if limit else 'No limit on firewalls downloading at once.')
    if stop_after:
        print(f"No more are started after {stop_after} fail with a corrupt image, stop responding, or don't answer.")
    print()
    if not confirm(f"Download on {len(plans)} firewall(s)?"):
        print("Nothing sent.")
        return
    group = ask_test_group(len(order), config['download_test_group']) if len(order) > 1 else 0

    outcomes, queue = {}, order
    batch = queue[:group] if 0 < group < len(queue) else queue
    while True:
        stage(f"Download ({len(batch)} firewall(s))" if batch is not queue else 'Download')
        results = run_jobs({fw: plans[fw] for fw in batch}, limit=limit, after=after, prior=outcomes,
                           stop_after=stop_after, busy_checked=checked,
                           queued={fw: reason for fw, reason in queued.items() if fw in batch},
                           queue_timeout=queue_timeout)
        for fw, outcome in results.items():
            if outcome[0] != NOT_STARTED:
                outcomes[fw] = outcome
        queue = [fw for fw in queue if fw not in outcomes]
        if not queue or any(result == STOPPED for result, _ in results.values()):
            break
        stopped = any(result == NOT_STARTED for result, _ in results.values())
        done = sum(outcomes[fw][0] == DONE for fw in batch if fw in outcomes)
        print()
        print_table(result_rows({fw: outcomes[fw] for fw in batch if fw in outcomes}))
        reason = ("Stopped after failures" if stopped
                  else f"Test group finished: {done} of {len(batch)} downloaded")
        print()
        if not confirm(f"{reason}. Start the remaining {len(queue)} firewall(s)?"):
            for fw in queue:
                outcomes[fw] = (NOT_STARTED, 'not started - you chose not to continue')
            break
        batch = queue
    for fw in order:
        outcomes.setdefault(fw, (NOT_STARTED, 'not started'))

    for fw, (result, detail) in outcomes.items():
        if result == UNKNOWN or (result == FAILED and explain_failure(detail)[0]):
            fw.download_failure = detail
    print()
    results = result_rows(outcomes, rows) + skipped_rows(selected, 'Result')
    print_table(results)
    write_results('PAN-OS download', results, selected)


def total_size(releases):
    kb = sum(int(r['size-kb']) for r in releases if r.get('size-kb', '').isdigit())
    return f"{kb / 1024:.0f} MB" if kb else '-'


def base_version(version):
    """The base image of a PAN-OS version's feature release: 11.2.10-h8 -> 11.2.0."""
    return '.'.join(version.split('.')[:2]) + '.0'


def revertable_version(fw):
    """The version in the firewall's revertable partition - what a software revert would boot -
    from 'debug swm status'. None if the firewall doesn't answer or has no revertable partition."""
    try:
        result = fw.op('<debug><swm><status></status></swm></debug>')
    except (PanError, requests.RequestException):
        return None
    match = re.search(r'REVERTABLE\s+(\d\S*)', message_text(result))
    return match[1] if match else None


def previous_version(fw, releases, current):
    """(version, where it came from) for the previously installed PAN-OS version, or (None, None).

    The revertable partition is the real answer. Failing that, a release the firewall marks as
    previous, and failing that, the newest downloaded image older than the installed one
    (skipping base images, which are rarely the version a firewall ran).
    """
    version = revertable_version(fw)
    if version:
        return version, 'revert partition'
    flagged = next((r['version'] for r in releases if r.get('previous') == 'yes'), None)
    if flagged:
        return flagged, 'marked previous'
    older = [r['version'] for r in releases if r.get('downloaded') == 'yes'
             and version_key(r['version']) < version_key(current)]
    guess = next((v for v in older if v != base_version(v)), older[0] if older else None)
    return (guess, 'newest older image') if guess else (None, None)


def cleanup_plan(fw, keep_previous=True):
    """What one firewall keeps and deletes: the installed version, the previous version if
    keep_previous, and the base image each kept version needs; every other downloaded image is deleted.

    Returns (keep line, images to delete). Raises PanError or RequestException if the image list can't be read.
    """
    releases = fw.cached_releases(PANOS)
    downloaded = {r['version'] for r in releases if r.get('downloaded') == 'yes'}
    current = current_release(releases)
    if not current:
        return 'Installed version not listed - run Check for Updates first', []
    installed = current['version']
    previous, source = previous_version(fw, releases, installed) if keep_previous else (None, None)

    def on_disk(version):
        return version if version in downloaded or version == installed else f"{version} (not downloaded)"

    bases = list(dict.fromkeys(base_version(v) for v in (installed, previous) if v))
    keep = {installed, previous, *bases}
    parts = [f"Current: {installed}"]
    if previous:
        parts.append(f"Previous: {on_disk(previous)}" + (f" ({source})" if source == 'newest older image' else ''))
    elif keep_previous:
        parts.append('Previous: none found')
    parts.append(f"Base image{'s' if len(bases) > 1 else ''}: " + ', '.join(on_disk(b) for b in bases))
    images = [r for r in releases if r.get('downloaded') == 'yes' and r['version'] not in keep]
    return '   '.join(parts), images


def ask_keep_previous():
    """True to keep the previous version as well as the installed one, False for the installed one
    only, None to cancel. Base images the kept versions need are kept either way."""
    print("\nKeep on each firewall (the base images the kept versions need are always kept):")
    print("  1) Current and previous version (for rollback)")
    print("  2) Current version only")
    chosen = pick('Keep', {1: True, 2: False}, single=True)
    return chosen[0] if chosen else None


def cleanup_panos_images(firewalls):
    """Delete every downloaded PAN-OS image except the installed version, optionally the previous
    version (for rollback), and the base image each needs, on the chosen firewalls, after one confirmation."""
    selected = select_firewalls('Clean up PAN-OS images on', firewalls)
    if not selected:
        return
    keep_previous = ask_keep_previous()
    if keep_previous is None:
        print("Nothing deleted.")
        return
    stage('Clean Up PAN-OS Images' + ('' if keep_previous else ' (current version only)'))
    plans = {}
    width = max(len(fw.name) for fw in selected)
    columns = shutil.get_terminal_size().columns
    for fw in selected:
        heading = f"{fw.number} - {fw.name.ljust(width)}   "
        try:
            keep, images = cleanup_plan(fw, keep_previous)
        except (PanError, requests.RequestException) as e:
            print(f"\n{heading}Could not list images: {connection_error_text(e)}")
            continue
        print(f"\n{heading}{keep}")
        if not images:
            print("    Nothing to delete")
            continue
        plans[fw] = images
        # Wrapped to the terminal so a long list stays readable at any width
        label = f"To be deleted ({len(images)}, {total_size(images)}): "
        print(textwrap.fill(', '.join(r['version'] for r in images), width=max(columns - 1, 60),
                            initial_indent=f"    {label}", subsequent_indent=' ' * (4 + len(label)),
                            break_on_hyphens=False))

    print()
    busy = leave_out_busy(plans) if plans else {}
    if not plans:
        print("\nNothing to delete.")
        return
    count = sum(len(images) for images in plans.values())
    print()
    if not confirm(f"Delete {count} PAN-OS image(s) on {len(plans)} firewall(s)?"):
        print("Nothing deleted.")
        return

    run_deletes(plans, PANOS, selected, busy)


def manage_panos_updates(firewalls, config):
    while True:
        choice = menu('Manage PAN-OS Updates', ['Check for Updates', 'Download PAN-OS Image',
                                                'Clean Up PAN-OS Images', 'Delete Downloaded PAN-OS Images'])
        if choice == '1':
            check_panos_updates(firewalls)
        elif choice == '2':
            download_panos(firewalls, config)
        elif choice == '3':
            cleanup_panos_images(firewalls)
        elif choice == '4':
            delete_downloaded(firewalls, PANOS)
        else:
            return


# ---------------------------------------------------------------- config snapshots

def file_safe(name):
    """name with the characters Windows doesn't allow in a file name replaced by '-'."""
    return UNSAFE_FILE_CHARS.sub('-', name).strip(' .') or 'firewall'


def device_name(fw):
    """The firewall's hostname for naming downloads, or the target as entered if it has none."""
    return file_safe(fw.hostname or fw.name)


def snapshot_name(day):
    """The name a snapshot is saved under on the firewall: '<YYYY-MM-DD>.xml'."""
    return f"{day.isoformat()}.xml"


def newest_snapshot(names):
    """The most recent snapshot: the latest <YYYY-MM-DD>.xml saved by this tool if there is one,
    otherwise the name with the latest date in it. None if no name has a date."""
    own = [name for name in names if SNAPSHOT_NAME.match(name)]
    if own:
        return max(own)
    dated = [(match[0], name) for name in names if (match := SNAPSHOT_DATE.search(name))]
    return max(dated)[1] if dated else None


def recent_snapshot(fw):
    """Name of the most recent snapshot on the firewall. If the list can't be read, falls back
    to the snapshot created this session. Raises PanError saying why there's none."""
    try:
        names = fw.saved_snapshots()
    except PanError as e:
        if fw.authenticated and fw.snapshot:
            print(f"{fw}: {e} - using {fw.snapshot}, created this session")
            return fw.snapshot
        raise
    newest = newest_snapshot(names)
    if not newest:
        raise PanError(f"no snapshot with a date in its name (found: {', '.join(names)})")
    return newest


def free_path(folder, name):
    """folder/name, or 'name (1)', 'name (2)'... if that file already exists. Never overwrites."""
    name = UNSAFE_FILE_CHARS.sub('-', Path(name).name) or 'snapshot.xml'
    path = folder / name
    number = 1
    while path.exists():
        path = folder / f"{Path(name).stem} ({number}){Path(name).suffix}"
        number += 1
    return path


def create_snapshots(firewalls):
    """Save the candidate configuration as a snapshot named after today's date on each chosen firewall."""
    selected = select_firewalls('Create a config snapshot on', firewalls)
    if not selected:
        return
    stage('Create Config Snapshot')
    name = snapshot_name(datetime.date.today())
    print(f"Snapshot name on each firewall: {name}")
    print("A snapshot holds the candidate configuration, including any changes that aren't committed yet.")
    if not confirm(f"Save {name} on {len(selected)} firewall(s)?"):
        print("Nothing saved.")
        return

    results = []
    for fw in selected:
        print(f"{fw}: saving {name}...")
        try:
            message = message_text(fw.op(f"<save><config><to>{escape(name)}</to></config></save>",
                                         fw.check_timeout))
        except (PanError, requests.RequestException) as e:
            print(f"{fw}: failed - {connection_error_text(e)}")
            outcome = EXPIRED if not fw.authenticated else FAILED
        else:
            print(f"{fw}: done" + (f" - {message}" if message else ''))
            fw.snapshot = name
            outcome = DONE
        results.append({**ident(fw), 'Snapshot': name, 'Result': outcome})
    print()
    print_table(results + skipped_rows(selected, 'Result'))


def download_snapshots(firewalls, config):
    """Save each chosen firewall's most recent snapshot to the download folder as <hostname>_<snapshot name>."""
    selected = select_firewalls('Download the most recent config snapshot from', firewalls)
    if not selected:
        return
    stage('Download Recent Config Snapshot')
    folder = config_folder(config['download_folder'])
    results = []
    for fw in selected:
        row = {**ident(fw), 'Snapshot': '-', 'Saved as': '-'}
        try:
            name = row['Snapshot'] = recent_snapshot(fw)
            print(f"{fw}: downloading {name}...")
            result = fw.op(f"<show><config><saved>{escape(name)}</saved></config></show>", fw.check_timeout)
            config = result.find('config') if result is not None else None
            if config is None:
                raise PanError(f"the firewall returned no configuration for {name}")
            folder.mkdir(parents=True, exist_ok=True)
            path = free_path(folder, f"{device_name(fw)}_{name}")
            path.write_bytes(b'<?xml version="1.0"?>\n' + ET.tostring(config))
        except (PanError, requests.RequestException, OSError) as e:
            print(f"{fw}: failed - {connection_error_text(e)}")
            row['Result'] = EXPIRED if not fw.authenticated else FAILED
        else:
            print(f"{fw}: saved {path}")
            row.update({'Saved as': path.name, 'Result': DONE})
        results.append(row)
    finish_downloads(results, selected, folder)


def finish_downloads(results, selected, folder):
    print()
    print_table(results + skipped_rows(selected, 'Result'))
    if any(row['Result'].startswith(DONE) for row in results):
        print(f"\nSaved in {folder}")


def download_device_state(firewalls, config):
    """Export each chosen firewall's device state (the config plus Panorama-pushed settings,
    certificates and keys) to the download folder as <hostname>_<YYYY-MM-DD>_device-state.tgz."""
    selected = select_firewalls('Download a system state backup from', firewalls)
    if not selected:
        return
    stage('Download System State Backup')
    folder = config_folder(config['download_folder'])
    today = datetime.date.today().isoformat()
    results = []
    for fw in selected:
        row = {**ident(fw), 'Saved as': '-', 'Size': '-'}
        print(f"{fw}: exporting the device state (up to {fw.check_timeout[1]}s)...")
        try:
            body = fw.export('device-state')
            folder.mkdir(parents=True, exist_ok=True)
            path = free_path(folder, f"{device_name(fw)}_{today}_device-state.tgz")
            path.write_bytes(body)
        except (PanError, requests.RequestException, OSError) as e:
            print(f"{fw}: failed - {connection_error_text(e)}")
            row['Result'] = EXPIRED if not fw.authenticated else FAILED
        else:
            # A .tgz starts with the gzip signature; anything else is saved but flagged
            note = '' if body[:2] == b'\x1f\x8b' else ' - WARNING: not a gzip file, check its contents'
            print(f"{fw}: saved {path}{note}")
            row.update({'Saved as': path.name, 'Size': f"{len(body) / 1024:.0f} KB",
                        'Result': DONE + (' (not gzip)' if note else '')})
        results.append(row)
    finish_downloads(results, selected, folder)


# ---------------------------------------------------------------- HA status validation

# Versions compared between the two units of a pair
HA_VERSION_FIELDS = ('PAN-OS', 'Apps & Threats', 'Antivirus')


def unit_text(fw):
    return f"#{fw.number} {fw.hostname or fw.expected_hostname or fw.name}"


def find_peer(fw, firewalls, need_ha=True):
    """The firewall in firewalls that fw's HA state names as its peer, or None if it isn't there.

    Matched by the peer serial number fw's HA detail reports, against each firewall's serial number
    (reported, or from the data file for one not connected yet). Failing that, by the peer's
    management IP against each firewall's own management IP, its HA management IP and the IP this
    session connects to - so a peer reached through NAT is still found. Hostnames are never used to
    pair firewalls. A firewall whose serial is known and differs never matches. With need_ha (the default) only
    firewalls whose HA state was read and shows HA are considered; without it, a listed firewall that
    isn't authenticated can match by IP too.
    """
    peer = fw.ha['peer']
    serial, mgmt_ip = peer.get('serial'), peer.get('mgmt_ip')
    candidates = []
    for other in firewalls:
        if other is fw:
            continue
        if other.ha is not None and not other.ha['enabled']:
            continue
        if need_ha and other.ha is None:
            continue
        candidates.append(other)
    def serials(other):
        """What other's serial number is: reported, or (not connected yet) from the data file."""
        local = other.ha['local'] if other.ha else {}
        found = {other.serial, local.get('serial')} - {None, ''}
        return found or ({other.known.get('serial')} - {None, ''})

    if serial:
        for other in candidates:
            if serial in serials(other):
                return other
    if mgmt_ip:
        for other in candidates:
            local = other.ha['local'] if other.ha else {}
            # A unit whose serial is known and differs is a different firewall, whatever its IP
            known = serials(other)
            if serial and known and serial not in known:
                continue
            if mgmt_ip in {other.mgmt_ip, local.get('mgmt_ip'), other.ip} - {None, ''}:
                return other
    return None


def ha_pair(fw, other):
    """One HA pair for the status table. fw is a connected unit; other is its connected peer, or None
    (then fw.peer, from correlate_ha, names a listed peer that isn't authenticated). The active (or
    active-primary) unit goes first."""
    units = sorted([fw] + ([other] if other else []), key=lambda u: u.ha['local']['state'] not in HA_ACTIVE_STATES)
    first, second = units[0], (units[1] if other else None)
    peer_view = second.ha['local'] if second else first.ha['peer']
    differences = [f"{name} {first.ha['local'][name]} / {peer_view[name]}" for name in HA_VERSION_FIELDS
                   if first.ha['local'].get(name) and peer_view.get(name)
                   and first.ha['local'][name] != peer_view[name]]
    return {
        'first': first,
        'second': second,
        'second_text': unit_text(second) if second else
                       f"{unit_text(first.peer)} ({'HA state unknown' if first.peer.authenticated else 'not authenticated'})"
                       if getattr(first, 'peer', None) else
                       f"{peer_view.get('mgmt_ip') or peer_view.get('serial') or 'peer'} (not in list)",
        'states': f"{state_text(first.ha['local']['state'])} / {state_text(peer_view.get('state'))}",
        'link': first.ha['peer'].get('conn') or '-',
        'sync': first.ha['running_sync'],
        'differences': differences,
    }


def sync_text(sync):
    return sync.capitalize() if sync else 'Unknown'


def ha_pairs(selected, firewalls):
    """The HA pairs among the selected firewalls, from each unit's latest HA state (fw.ha), for the
    pairs table: [ha_pair(...)], plus {fw: [pairing notes]}. A connected
    peer that wasn't selected is read too, so both sides are current."""
    # Re-pair from the fresh states (a failover or a fixed config may have changed them)
    notes = correlate_ha(firewalls)
    record_devices(selected)
    connected = [fw for fw in firewalls if fw.authenticated]
    pairs, paired = [], set()
    for fw in selected:
        if fw in paired or not fw.ha or not fw.ha['enabled']:
            continue
        other = find_peer(fw, connected)
        if other and other not in selected:
            poll_ha(other)
            other = other if other.ha and other.ha['enabled'] else None
        paired.update(u for u in (fw, other) if u)
        pairs.append(ha_pair(fw, other))
    return pairs, notes


def print_ha_pairs(pairs, selected, notes):
    """One row per HA pair: both units, their states, the peer link, config sync and any version difference."""
    stage('HA Pairs')
    if pairs:
        print_table([{
            '#': str(number),
            'Unit 1': unit_text(pair['first']),
            'Unit 2': pair['second_text'],
            'HA State': pair['states'],
            'Peer Link': pair['link'],
            'Config Sync': sync_text(pair['sync']),
            'Versions': '; '.join(pair['differences']) or 'Match',
        } for number, pair in enumerate(pairs, 1)])
    else:
        print("No HA pairs among the chosen firewalls.")
    standalone = [fw for fw in selected if fw.ha is not None and not fw.ha['enabled']]
    unknown = [fw for fw in selected if fw.ha is None]
    if standalone:
        print(f"\nStandalone: {', '.join(unit_text(fw) for fw in standalone)}")
    if unknown:
        print(f"\nHA state unknown: {', '.join(unit_text(fw) for fw in unknown)}")
    flagged = [(fw, note) for fw in selected for note in notes.get(fw, [])]
    if flagged:
        print("\nCheck these HA pairs:")
        for fw, note in flagged:
            print(f"  {fw}: {note}")


# ---------------------------------------------------------------- health check

# Run Health Check (Palo Firewall Management option 7). Every check is read-only. PASS and FAIL as above.
WARN, ERROR, NOT_APPLICABLE = 'WARN', 'ERROR', 'N/A'
# Order in the details: the worst first
STATUS_ORDER = {FAIL: 0, ERROR: 1, WARN: 2, PASS: 3, NOT_APPLICABLE: 4}
CHASSIS_LEDS_CMD = '<show><system><state><filter>chassis.leds</filter></state></system></show>'
MP_EXPORTS_CMD = '<show><system><state><filter>sys.monitor.s0.mp.exports</filter></state></system></show>'
RESOURCES_CMD = '<show><system><resources></resources></system></show>'
ENVIRONMENT_CMD = '<show><system><environmentals></environmentals></system></show>'
SESSION_INFO_CMD = '<show><session><info></info></session></show>'
RESOURCE_MONITOR_CMD = ('<show><running><resource-monitor><minute><last>5</last></minute></resource-monitor>'
                        '</running></show>')
INTERFACES_CMD = '<show><interface>all</interface></show>'
LOGGING_STATUS_CMD = '<show><logging-status></logging-status></show>'
PANORAMA_STATUS_CMD = '<show><panorama-status></panorama-status></show>'
LICENSE_INFO_CMD = '<request><license><info></info></license></request>'
PENDING_CHANGES_CMD = '<check><pending-changes></pending-changes></check>'
# Read from the firewall's own (candidate) config with type=config action=get
CERTIFICATE_XPATHS = ('/config/shared/certificate', '/config/devices/entry/vsys/entry/certificate')
# Most System log entries one health check reads from a firewall
HEALTH_LOG_LIMIT = 1000
UPTIME = re.compile(r'(\d+)\s+days?,\s*(\d+):(\d+):(\d+)')
# chassis.leds: { 'alarm': Off, 'fans': Green, 'ha': Off, 'status': Green, 'temp': Green, }
LED = re.compile(r"'([\w.-]+)'\s*:\s*'?([^,'}]*?)'?\s*(?:,|\})")
LED_PROBLEM = re.compile(r'red|amber|yellow|orange', re.IGNORECASE)
MP_CPU = re.compile(r"""["']cpu["']\s*:\s*\{[^}]{0,800}?["']1minavg["']\s*:\s*([\d.]+)""")
TOP_CPU_IDLE = re.compile(r'([\d.]+)\s*%?\s*id\b')
TOP_MEM = re.compile(r'^\s*(?:[KMGT]i?B\s+)?Mem\s*:(.*)$', re.MULTILINE | re.IGNORECASE)
TOP_SWAP = re.compile(r'^\s*(?:[KMGT]i?B\s+)?Swap\s*:(.*)$', re.MULTILINE | re.IGNORECASE)
TOP_FIELD = re.compile(r'([\d.]+)\s*[kmg]?\s+(total|free|used|buff/cache|buffers|avail|cached)', re.IGNORECASE)
GOOD_HA_STATES = {'active', 'passive', 'active-primary', 'active-secondary'}
HA_LINKS = (('conn-ha1', 'HA1', 'ha1_down'), ('conn-ha2', 'HA2', 'ha2_down'),
            ('conn-ha1-backup', 'HA1 backup', 'backup_link_down'), ('conn-ha2-backup', 'HA2 backup', 'backup_link_down'))
# Logical interfaces without a port of their own, and the HA and management ports (the HA check covers those)
UNCHECKED_INTERFACE = re.compile(r'^(tunnel|loopback|vlan|ha\d|mgmt)', re.IGNORECASE)
# A show logging-status row for a log type that has been forwarded: type, last created, last forwarded
LOG_FORWARDED_ROW = re.compile(r'^\s*[\w-]+\s+\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\s+\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}',
                               re.MULTILINE)
JOB_TIME = '%Y/%m/%d %H:%M:%S'
PERMISSION_ERROR = re.compile(r'privilege|permission|unauthori|not allowed', re.IGNORECASE)


class HealthContext:
    """What every check of one firewall shares: the firewall, its show system info reply and its own
    clock (log and job times are in the firewall's time zone)."""

    def __init__(self, fw, info):
        self.fw, self.info = fw, info
        self.now, self.clock_note = firewall_clock(info)
        model = (info.findtext('model') or '').strip().upper()
        self.vm = model.startswith('PA-VM') or info.find('vm-license') is not None


def firewall_clock(info):
    """(the firewall's local time from show system info, note): 'Mon Nov 16 19:34:01 2026'. This PC's
    clock, with a note saying so, if it can't be read."""
    text = re.sub(r'(\d+:\d+:\d+) [A-Za-z]{2,5} ', r'\1 ', ' '.join((info.findtext('time') or '').split()))
    try:
        return datetime.datetime.strptime(text, '%a %b %d %H:%M:%S %Y'), ''
    except ValueError:
        return datetime.datetime.now(), f"the firewall's clock couldn't be read ({text or 'no time'}) - this PC's clock used"


def text_of(element):
    """All the text in a reply element - for the commands that answer with a block of CLI text."""
    return '' if element is None else ''.join(element.itertext())


def severity_status(severity):
    """'warn' -> WARN, 'fail' -> FAIL, 'off' -> None (not reported)."""
    return {'warn': WARN, 'fail': FAIL}.get(severity)


def over(value, warn, fail):
    """FAIL, WARN or PASS for a value where higher is worse. A threshold of 0 is off."""
    if fail and value >= fail:
        return FAIL
    if warn and value >= warn:
        return WARN
    return PASS


def below(value, warn, fail):
    """FAIL, WARN or PASS for a value where lower is worse (uptime). A threshold of 0 is off."""
    if fail and value < fail:
        return FAIL
    if warn and value < warn:
        return WARN
    return PASS


def days_left_status(days, warn, fail):
    """For a license or certificate with this many days left: expired is always a FAIL."""
    if days < 0 or (fail and days <= fail):
        return FAIL
    if warn and days <= warn:
        return WARN
    return PASS


def hc_system_info(ctx, s):
    info, found, ok = ctx.info, [], []
    uptime = ' '.join((info.findtext('uptime') or '').split())
    match = UPTIME.search(uptime)
    if match:
        hours = int(match[1]) * 24 + int(match[2]) + int(match[3]) / 60
        status = below(hours, s('uptime_warn_hours'), s('uptime_fail_hours'))
        if status == PASS:
            ok.append(f"up {uptime}")
        else:
            found.append((status, f"up only {uptime} - it restarted recently",
                          "Check the System log for why it restarted: a planned restart, a crash or a power loss."))
    cert = (info.findtext('device-certificate-status') or '').strip()
    status = severity_status(s('device_certificate'))
    if cert and cert.lower() != 'valid' and status:
        found.append((status, f"device certificate {cert}",
                      "Fetch the device certificate: Device > Setup > Management > Device Certificate (needs a "
                      "one-time password from the Customer Support Portal)."))
    elif cert:
        ok.append(f"device certificate {cert}")
    if ctx.vm:
        vm_license = (info.findtext('vm-license') or '').strip()
        status = severity_status(s('vm_license'))
        if vm_license.lower() in ('', 'none', 'unknown') and status:
            found.append((status, f"no VM license (vm-license {vm_license or 'empty'})",
                          "License the VM-Series: Device > Licenses, or request license fetch."))
        elif vm_license:
            ok.append(f"VM license {vm_license}")
    return found or [(PASS, '; '.join(ok) or 'nothing to report', '')]


def hc_chassis_leds(ctx, s):
    if ctx.vm:
        return [(NOT_APPLICABLE, 'VM-Series - no chassis LEDs', '')]
    leds = [(name, value.strip()) for name, value in LED.findall(text_of(ctx.fw.op(CHASSIS_LEDS_CMD)))]
    if not leds:
        return [(NOT_APPLICABLE, 'no chassis LEDs reported', '')]
    ignore = {name.lower() for name in s('ignore')}
    bad = [f"{name} {value}" for name, value in leds if name.lower() not in ignore
           and ((name.lower() == 'alarm' and value.lower() not in ('off', '')) or LED_PROBLEM.search(value))]
    status = severity_status(s('not_green'))
    if bad and status:
        return [(status, f"LED {', '.join(bad)}",
                 "Look at the firewall and its hardware guide for what the LED means; Environmentals and the "
                 "System log usually say which part.")]
    return [(PASS, ', '.join(f"{name} {value}" for name, value in leds), '')]


def sensor_reading(values):
    for tag, unit in (('DegreesC', ' C'), ('RPMs', ' RPM'), ('Volts', ' V')):
        if values.get(tag):
            return f" ({values[tag]}{unit})"
    return ''


SENSOR_HINTS = {
    'thermal': "Check the airflow, the fans and the room temperature.",
    'fan': "A fan has failed or is failing - replace it (RMA).",
    'fantray': "A fan tray has failed or is failing - replace it (RMA).",
    'power': "Check the power feed and the power supply.",
    'power-supply': "Check the power supply and its power feed.",
}


def hc_environment(ctx, s):
    if ctx.vm:
        return [(NOT_APPLICABLE, 'VM-Series - no hardware sensors', '')]
    result = ctx.fw.op(ENVIRONMENT_CMD)
    sensors = [(section.tag, {child.tag: (child.text or '').strip() for child in entry})
               for section in (result if result is not None else []) for entry in section.iter('entry')]
    if not sensors:
        return [(NOT_APPLICABLE, 'no hardware sensors reported', '')]
    alarm, missing, margin = severity_status(s('alarm')), severity_status(s('power_supply_missing')), s('temp_margin_warn')
    found = []
    for section, values in sensors:
        name = values.get('description') or f"{section} slot {values.get('slot', '?')}"
        if section == 'power-supply' and values.get('Inserted', '').lower() == 'false':
            if missing:
                found.append((missing, f"{name}: not inserted",
                              "Insert the power supply - or, on a single-PSU install, set "
                              "environment_power_supply_missing to OFF."))
            continue
        if values.get('alarm', '').lower() == 'true':
            if alarm:
                found.append((alarm, f"{name}: alarm{sensor_reading(values)}", SENSOR_HINTS.get(section, '')))
            continue
        if section == 'thermal' and margin:
            try:
                degrees, highest = float(values['DegreesC']), float(values['max'])
            except (KeyError, ValueError):
                continue
            if highest - degrees <= margin:
                found.append((WARN, f"{name}: {degrees:g} C, within {margin} C of its {highest:g} C maximum",
                              SENSOR_HINTS['thermal']))
    return found or [(PASS, f"{len(sensors)} sensors, no alarms", '')]


def top_fields(pattern, text):
    match = pattern.search(text)
    return {label.lower(): float(number) for number, label in TOP_FIELD.findall(match[1])} if match else {}


def parse_top(text):
    """{'cpu': %, 'memory': % used, 'swap': % used} from show system resources (top), whichever it has.
    Memory used leaves out buffers and cache. Handles both top formats (MiB Mem ... avail Mem, and the
    older Mem: ...k total with buffers and cached)."""
    values = {}
    idle = TOP_CPU_IDLE.search(text)
    if idle:
        values['cpu'] = max(0.0, 100 - float(idle[1]))
    memory, swap = top_fields(TOP_MEM, text), top_fields(TOP_SWAP, text)
    if memory.get('total'):
        if 'avail' in swap:
            used = memory['total'] - swap['avail']
        elif 'buffers' in memory or 'cached' in swap:
            used = memory.get('used', 0) - memory.get('buffers', 0) - swap.get('cached', 0)
        else:
            used = memory.get('used', memory['total'] - memory.get('free', 0) - memory.get('buff/cache', 0))
        values['memory'] = max(0.0, used * 100 / memory['total'])
    if swap.get('total'):
        values['swap'] = swap.get('used', 0) * 100 / swap['total']
    return values


MP_HINTS = {
    'cpu': "See what's busy with show system resources (top): a commit, a log query, a report or a "
           "process stuck at high CPU.",
    'memory': "show system resources: look for a process using a lot of memory. A process (or firewall) "
              "restart may be needed - check with TAC first.",
    'swap': "Swap in use means management memory is short - see the memory figure and show system resources.",
}


def hc_mp_resources(ctx, s):
    """Management CPU (the 1-minute average), memory and swap. top's %Cpu(s) line is never used for the
    CPU: on models whose dataplane shares the CPU (pan_task busy-polls its cores) it reads 80-100% on an
    idle firewall. If the 1-minute average can't be read, CPU isn't judged and the reply goes to the run
    log, so its format can be checked."""
    cpu, exports = None, ''
    try:
        exports = text_of(ctx.fw.op(MP_EXPORTS_CMD))
        match = MP_CPU.search(exports)
        cpu = float(match[1]) if match else None
    except PanError as e:
        if not ctx.fw.authenticated:
            raise
        exports = f"(error: {e})"
    top = text_of(ctx.fw.op(RESOURCES_CMD))
    values = parse_top(top)
    values['cpu'] = cpu
    if cpu is None:
        log_only(f"{ctx.fw}: health check - no management CPU 1-minute average in "
                 f"sys.monitor.s0.mp.exports, so CPU wasn't judged. Reply: {' '.join(exports.split())[:1500]}"
                 f"\n  show system resources (first lines): {' | '.join(top.strip().splitlines()[:12])}")
    found, ok = [], []
    for key, label in (('cpu', 'CPU'), ('memory', 'memory'), ('swap', 'swap')):
        if values.get(key) is None:
            continue
        status = over(values[key], s(f'{key}_warn'), s(f'{key}_fail'))
        text = f"{label} {values[key]:.0f}%" + (' (1-minute average)' if key == 'cpu' else '')
        if status == PASS:
            ok.append(text)
        else:
            found.append((status, f"management {text}", MP_HINTS[key]))
    if not found and not ok:
        raise PanError("show system resources didn't give memory figures, and the CPU average couldn't be read")
    if cpu is None:
        ok.append("CPU not read (no 1-minute average reported)")
    return found or [(PASS, ', '.join(ok), '')]


def numbers(text):
    """'1,2,3' -> [1.0, 2.0, 3.0]"""
    return [float(n) for n in re.findall(r'\d+(?:\.\d+)?', text or '')]


DATAPLANE_HINTS = {
    'cpu': "See what's using the dataplane: show running resource-monitor, and the traffic and session trend "
           "(Monitor > ACC).",
    'packet_buffer': "Buffer pressure: look for a traffic burst or a flood (show counter global filter delta yes "
                     "severity drop) and check Zone/DoS Protection.",
    'packet_descriptor': "Descriptor pressure: look for a traffic burst or a flood (show counter global filter "
                         "delta yes severity drop).",
}


def hc_dataplane(ctx, s):
    result = ctx.fw.op(RESOURCE_MONITOR_CMD)
    processors = result.find('resource-monitor/data-processors') if result is not None else None
    if processors is None or not len(processors):
        return [(NOT_APPLICABLE, 'no dataplane figures reported', '')]
    found, ok = [], []

    def judge(key, value, text):
        status = over(value, s(f'{key}_warn'), s(f'{key}_fail'))
        if status == PASS:
            ok.append(text)
        else:
            found.append((status, text, DATAPLANE_HINTS[key]))

    for dp in processors:
        minute = dp.find('minute')
        minute = dp if minute is None else minute
        name = dp.tag + ' ' if len(processors) > 1 else ''
        loads = [sum(v) / len(v) for v in (numbers(e.findtext('value')) for e in minute.findall('cpu-load-average/entry')) if v]
        if loads:
            judge('cpu', sum(loads) / len(loads),
                  f"{name}CPU {sum(loads) / len(loads):.0f}% (busiest core {max(loads):.0f}%)")
        # 'packet buffer (average)' and '(maximum)', or plain 'packet buffer' on older releases. Where both
        # are reported, the average series is judged (its highest minute); the maximum is a momentary peak.
        entries = [((e.findtext('name') or '').strip(), numbers(e.findtext('value')))
                   for e in minute.findall('resource-utilization/entry')]
        labels = {label.lower() for label, _ in entries}
        for label, values in entries:
            lower = label.lower()
            key = ('packet_buffer' if lower.startswith('packet buffer') else
                   'packet_descriptor' if lower.startswith('packet descriptor') else None)
            if not key or not values or ('(maximum)' in lower and lower.replace('(maximum)', '(average)') in labels):
                continue
            judge(key, max(values), f"{name}{label} {max(values):.0f}%")
    if not found and not ok:
        return [(NOT_APPLICABLE, 'no dataplane figures reported', '')]
    return found or [(PASS, ', '.join(ok) + ' (5-minute)', '')]


def hc_sessions(ctx, s):
    result = ctx.fw.op(SESSION_INFO_CMD)
    try:
        active, maximum = (int((result.findtext(tag) or '').strip()) for tag in ('num-active', 'num-max'))
    except (AttributeError, ValueError):
        raise PanError("show session info gave no session counts")
    if not maximum:
        return [(NOT_APPLICABLE, f"{active:,} sessions (no maximum reported)", '')]
    percent = active * 100 / maximum
    status = over(percent, s('used_warn'), s('used_fail'))
    text = f"{active:,} of {maximum:,} sessions ({percent:.0f}%)"
    return [(status, text, '' if status == PASS else
             "Find the top sources (Monitor > ACC, show session all filter count yes), check the session "
             "timeouts, and look for a flood.")]


def hc_ha(ctx, s):
    fw = ctx.fw
    result = fw.op(HA_STATE_CMD)
    fw.ha = parse_ha(result)
    if not fw.ha['enabled']:
        return [(NOT_APPLICABLE, 'HA not enabled (standalone)', '')]
    group = result.find('group')
    group = result if group is None else group
    local, peer = group.find('local-info'), group.find('peer-info')
    state, peer_state = fw.ha['local']['state'], fw.ha['peer'].get('state', '')
    found = []

    def add(setting, text, hint):
        status = severity_status(s(setting))
        if status:
            found.append((status, text, hint))

    if state not in GOOD_HA_STATES:
        add('state', f"this unit is {state_text(state)}",
            "show high-availability all gives the reason (suspended by an admin, a link or path monitor, a "
            "version mismatch...). request high-availability state functional brings back a suspended unit.")
    elif state == peer_state == 'active':
        add('state', "both units are Active",
            "Split brain: the units can't see each other over HA1 - check the HA1 links (and backup) now.")
    connection = fw.ha['peer'].get('conn', '').lower()
    if connection and connection != 'up':
        peer_name = fw.ha['peer'].get('mgmt_ip') or fw.ha['peer'].get('serial') or 'peer'
        add('peer_down', f"peer {peer_name} not connected ({connection}, peer state {state_text(peer_state)})",
            "Check the peer is up, and the HA1 link between the units.")
    for tag, label, setting in HA_LINKS:
        link = peer.find(tag) if peer is not None else None
        link_status = (link.findtext('conn-status') or '').strip().lower() if link is not None else ''
        if link_status and link_status != 'up':
            add(setting, f"{label} link {link_status}", f"Check the {label} cable, ports and IP settings on both units.")
    sync = fw.ha['running_sync']
    if sync and sync != 'synchronized' and (group.findtext('running-sync-enabled') or 'yes').strip().lower() == 'yes':
        add('config_sync', f"config {sync_text(sync)}",
            "Sync it by hand from the active unit once the cause is fixed (Dashboard > High Availability > "
            "Sync to peer, or request high-availability sync-to-remote running-config).")
    mismatched = [child.tag[:-len('-compat')] for child in (local if local is not None else [])
                  if child.tag.endswith('-compat') and (child.text or '').strip().lower() == 'mismatch']
    if mismatched:
        add('version_mismatch', f"doesn't match the peer: {', '.join(mismatched)}",
            "Bring both units to the same PAN-OS and content versions.")
    summary = f"{state_text(state)}, peer {state_text(peer_state)}, config {sync_text(sync)}"
    return found or [(PASS, summary, '')]


def hc_interfaces(ctx, s):
    result = ctx.fw.op(INTERFACES_CMD)
    ports = {(e.findtext('name') or '').strip(): (e.findtext('state') or '').strip().lower()
             for e in (result.findall('hw/entry') if result is not None else [])}
    ignore = {name.lower() for name in s('ignore')}
    status = severity_status(s('down'))
    found, checked = [], 0
    for entry in result.findall('ifnet/entry') if result is not None else []:
        name = (entry.findtext('name') or '').strip()
        zone, ip, fwd = ((entry.findtext(tag) or '').strip() for tag in ('zone', 'ip', 'fwd'))
        if not name or UNCHECKED_INTERFACE.match(name) or fwd.lower() == 'ha':
            continue
        configured = [text for value, text in ((zone, f"zone {zone}"), (ip, ip), (fwd, fwd))
                      if value and value.upper() != 'N/A']
        port = name.split('.')[0]
        if not configured or name.lower() in ignore or port.lower() in ignore or port not in ports:
            continue
        checked += 1
        if ports[port] == 'down' and status:
            found.append((status, f"{name} down ({', '.join(configured)})",
                          "Check the cable, the transceiver and the switch port - or, if it's meant to be down, "
                          "add it to interfaces_ignore."))
    return found or [(PASS, f"{checked} configured interface(s) up", '')]


def hc_system_log(ctx, s):
    from collections import Counter
    hours = s('hours')
    since = ctx.now - datetime.timedelta(hours=hours)
    query = f"( severity geq high ) and ( receive_time geq '{since:%Y/%m/%d %H:%M:%S}' )"
    try:
        entries = fetch_logs(ctx.fw, 'system', query, HEALTH_LOG_LIMIT, ctx.fw.check_timeout[1])
    except PanError as e:
        raise PanError(log_failure_text(e), e.status_code)
    exclude = {eventid.lower() for eventid in s('exclude_eventids')}
    counted = [e for e in entries if (e.get('eventid') or '').lower() not in exclude]
    capped = '+' if len(entries) >= HEALTH_LOG_LIMIT else ''
    found, totals = [], []
    for severity in ('critical', 'high'):
        matching = [e for e in counted if (e.get('severity') or '').lower() == severity]
        totals.append(f"{len(matching)}{capped if matching else ''} {severity}")
        status = over(len(matching), s(f'{severity}_warn'), s(f'{severity}_fail'))
        if status == PASS:
            continue
        top = Counter(e.get('eventid') or '?' for e in matching).most_common(5)
        latest = matching[0]
        found.append((status, f"{len(matching)}{capped} {severity} in {hours}h ({', '.join(f'{eventid} x{n}' for eventid, n in top)}); "
                              f"latest {log_time(latest)}: {(latest.get('opaque') or '')[:150]}",
                      f"Monitor > Logs > System, filter ( severity eq {severity} ). Known noise can go in "
                      f"system_log_exclude_eventids."))
    excluded = len(entries) - len(counted)
    summary = f"{', '.join(totals)} in {hours}h" + (f" ({excluded} excluded by event ID)" if excluded else '')
    return found or [(PASS, summary, '')]


def hc_log_forwarding(ctx, s):
    text = text_of(ctx.fw.op(LOGGING_STATUS_CMD))
    connected = re.findall(r'[^\n]*\bactive and connected\b[^\n]*', text, re.IGNORECASE)
    forwarded = LOG_FORWARDED_ROW.findall(text)
    if connected or forwarded:
        return [(PASS, ' '.join(connected[0].split()) if connected else
                 f"forwarding - {len(forwarded)} log type(s) with a last-forwarded time", '')]
    reasons = sorted({' '.join(line.split()) for line in re.findall(r'[^\n]*Not Sending[^\n]*', text, re.IGNORECASE)})
    detail = f"logs not forwarded ({'; '.join(reasons[:3]) or 'no forwarding destination reported'})"
    status = severity_status(s('not_forwarding'))
    if not status:
        return [(NOT_APPLICABLE, detail, '')]
    return [(status, detail,
             "Check the Panorama / Log Collector connection (show logging-status, Device > Log Settings). Syslog "
             "isn't shown here - turn log_forwarding off for a firewall that only logs locally or to syslog.")]


def hc_panorama(ctx, s):
    text = text_of(ctx.fw.op(PANORAMA_STATUS_CMD))
    servers = re.findall(r'Panorama Server\s*(\d+)\s*:\s*(\S+)(.*?)(?=Panorama Server|\Z)', text, re.DOTALL)
    if not servers:
        return [(NOT_APPLICABLE, 'not managed by Panorama', '')]
    status = severity_status(s('disconnected'))
    found, ok = [], []
    for number, address, rest in servers:
        match = re.search(r'Connected\s*:\s*(\w+)', rest)
        if match and match[1].lower() == 'yes':
            ok.append(f"Panorama {address} connected")
        elif status:
            found.append((status, f"Panorama server {number} ({address}) not connected",
                          "Check the route and that TCP 3978 to Panorama is open, and that Panorama has this "
                          "firewall's serial number."))
    return found or [(PASS, '; '.join(ok) or 'Panorama status read', '')]


def license_date(text):
    """A license's expiry ('November 01, 2026') as a date; None for 'Never'. ValueError if unreadable."""
    text = ' '.join(text.split())
    if text.lower() == 'never':
        return None
    for layout in ('%B %d, %Y', '%b %d, %Y', '%Y/%m/%d', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(text, layout).date()
        except ValueError:
            pass
    raise ValueError(text)


def hc_licenses(ctx, s):
    result = ctx.fw.op(LICENSE_INFO_CMD)
    # A renewal leaves the old entry beside the new one, so each feature keeps its latest expiry
    best = {}
    for entry in result.iter('entry') if result is not None else []:
        feature = (entry.findtext('feature') or entry.findtext('description') or '').strip()
        if not feature:
            continue
        expires = (entry.findtext('expires') or '').strip()
        try:
            date = license_date(expires)
            rank = (2, datetime.date.max) if date is None else (1, date)
        except ValueError:
            date, rank = expires, (0, datetime.date.min)
        expired = (entry.findtext('expired') or '').strip().lower() == 'yes'
        if feature not in best or rank > best[feature][0]:
            best[feature] = (rank, date, expired)
    if not best:
        return [(NOT_APPLICABLE, 'no licenses installed', '')]
    ignore = {name.lower() for name in s('ignore')}
    today = ctx.now.date()
    found, dated = [], []
    for feature, (rank, date, expired) in sorted(best.items()):
        if feature.lower() in ignore or rank[0] != 1:
            continue
        days = (date - today).days
        status = FAIL if expired else days_left_status(days, s('expiry_warn_days'), s('expiry_fail_days'))
        dated.append((days, feature, date))
        if status != PASS:
            found.append((status, f"{feature} {'expired' if days < 0 else 'expires'} {date:%Y-%m-%d}"
                                  + ('' if days < 0 else f" ({days} days)"),
                          "Renew it on the Customer Support Portal, then Device > Licenses > Retrieve license keys. "
                          "If it's no longer used, add it to licenses_ignore."))
    if found:
        return found
    if dated:
        days, feature, date = min(dated)
        return [(PASS, f"{len(best)} license(s); next to expire: {feature} {date:%Y-%m-%d} ({days} days)", '')]
    return [(PASS, f"{len(best)} license(s), none expiring", '')]


def hc_disk(ctx, s):
    disks = parse_disk_space(text_of(ctx.fw.op(DISK_SPACE_CMD)))
    if not disks:
        raise PanError("show system disk-space gave no partitions")
    ignore = set(s('ignore'))
    panrepo_fail = s('panrepo_free_fail_gb')
    found, ok = [], []
    for mount, sizes in disks.items():
        total = sizes['used'] + sizes['free']
        if mount in ignore or not total:
            continue
        percent = sizes['used'] * 100 / total
        status = over(percent, s('used_warn'), s('used_fail'))
        text = f"{mount} {percent:.0f}% used, {sizes['free'] / 1024:.1f} GB free"
        if mount == PANREPO and panrepo_fail and sizes['free'] < panrepo_fail * 1024:
            status = FAIL
            text += f" (under {panrepo_fail} GB)"
        if status == PASS:
            ok.append((percent, mount))
        else:
            found.append((status, text,
                          "Free space: Delete old PAN-OS images and content (Manage PAN-OS Updates / Manage Content "
                          "Updates), old config snapshots and tech-support files."))
    if found:
        return found
    percent, mount = max(ok, default=(0, '-'))
    return [(PASS, f"{len(ok)} partition(s); fullest {mount} {percent:.0f}%", '')]


def hc_pending_changes(ctx, s):
    answer = text_of(ctx.fw.op(PENDING_CHANGES_CMD)).strip().lower()
    status = severity_status(s('uncommitted'))
    if answer == 'yes' and status:
        return [(status, "the candidate config has changes that aren't committed",
                 "Commit them, or revert them (Config > Revert Changes) - an uncommitted change goes live with "
                 "the next commit, whoever makes it.")]
    return [(PASS, 'no uncommitted changes' if answer == 'no' else f"check pending-changes: {answer or 'no answer'}", '')]


def hc_jobs(ctx, s):
    result = ctx.fw.op(JOBS_ALL_CMD)
    hours, running_limit = s('hours'), s('running_warn_minutes')
    since = ctx.now - datetime.timedelta(hours=hours)
    failed, running = [], []
    for job in result.iter('job') if result is not None else []:
        values = {child.tag: (child.text or '').strip() for child in job if len(child) == 0}
        try:
            queued = datetime.datetime.strptime(' '.join(values.get('tenq', '').split()), JOB_TIME)
        except ValueError:
            continue
        status, outcome = values.get('status', '').upper(), values.get('result', '').upper()
        text = f"{values.get('id', '?')} {values.get('type') or 'job'} ({queued:%Y-%m-%d %H:%M})"
        if status == 'FIN' and outcome == 'FAIL' and queued >= since:
            failed.append(text)
        elif status == 'ACT' and running_limit and ctx.now - queued >= datetime.timedelta(minutes=running_limit):
            running.append(f"{text}, {int((ctx.now - queued).total_seconds() // 60)} min")
    found = []
    status = severity_status(s('failed'))
    if failed and status:
        found.append((status, f"{len(failed)} failed job(s) in {hours}h: {', '.join(failed[:5])}"
                              + (f" and {len(failed) - 5} more" if len(failed) > 5 else ''),
                      "show jobs id <id> gives the reason."))
    if running:
        found.append((WARN, f"still running: {', '.join(running[:5])}",
                      "show jobs id <id>: check it's progressing, not stuck."))
    return found or [(PASS, f"no failed jobs in {hours}h", '')]


def certificate_days(entry):
    """Days until a certificate entry (from the config) expires, or None if it doesn't say."""
    epoch = (entry.findtext('expiry-epoch') or '').strip()
    if epoch.isdigit():
        return (int(epoch) - time.time()) / 86400
    text = ' '.join((entry.findtext('not-valid-after') or '').split())
    try:
        return (datetime.datetime.strptime(text, '%b %d %H:%M:%S %Y GMT') - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).total_seconds() / 86400
    except ValueError:
        return None


def hc_certificates(ctx, s):
    certificates = {}
    for xpath in CERTIFICATE_XPATHS:
        result = ctx.fw.post({'type': 'config', 'action': 'get', 'xpath': xpath}).find('result')
        for entry in result.iter('entry') if result is not None else []:
            days = certificate_days(entry)
            if entry.get('name') and days is not None:
                certificates[entry.get('name')] = days
    if not certificates:
        return [(NOT_APPLICABLE, "no certificates in the firewall's own config", '')]
    ignore = {name.lower() for name in s('ignore')}
    found, checked = [], []
    for name, days in sorted(certificates.items(), key=lambda item: item[1]):
        if name.lower() in ignore:
            continue
        checked.append((days, name))
        status = days_left_status(int(days // 1), s('expiry_warn_days'), s('expiry_fail_days'))
        if status != PASS:
            found.append((status, f"{name} {'expired' if days < 0 else 'expires in'} "
                                  f"{f'{-days:.0f} days ago' if days < 0 else f'{days:.0f} days'}",
                          "Renew or replace it and update every profile that uses it (Device > Certificate "
                          "Management). If it's not used, delete it or add it to certificates_ignore."))
    if found or not checked:
        return found or [(PASS, 'every certificate is ignored', '')]
    days, name = checked[0]
    return [(PASS, f"{len(checked)} certificate(s); next to expire: {name} in {days:.0f} days", '')]


HEALTH_FUNCTIONS = {
    'system_info': hc_system_info, 'chassis_leds': hc_chassis_leds, 'environment': hc_environment,
    'mp_resources': hc_mp_resources, 'dataplane': hc_dataplane, 'sessions': hc_sessions, 'ha': hc_ha,
    'interfaces': hc_interfaces, 'system_log': hc_system_log, 'log_forwarding': hc_log_forwarding,
    'panorama': hc_panorama, 'licenses': hc_licenses, 'disk': hc_disk, 'pending_changes': hc_pending_changes,
    'jobs': hc_jobs, 'certificates': hc_certificates,
}


def run_health(fw, health):
    """Every enabled check on fw, in order: [(check label, status, detail, remediation)]. A check whose
    command fails is an ERROR and the rest still run - unless the firewall stops answering or the
    session ends, which stops the rest."""
    try:
        info = fw.system_info()
    except (PanError, requests.RequestException) as e:
        return [('Connection', ERROR, f"show system info failed: {connection_error_text(e)} - no checks run",
                 "Check the firewall is reachable; Retry Authentication if its session ended.")]
    ctx = HealthContext(fw, info)
    findings = []
    for key, label in HEALTH_CHECKS:
        if not health[f'{key}_enabled']:
            continue

        def setting(name, key=key):
            return health[f'{key}_{name}']
        try:
            findings += [(label, status, detail, hint) for status, detail, hint in HEALTH_FUNCTIONS[key](ctx, setting)]
        except requests.ConnectionError as e:
            findings.append((label, ERROR, f"could not read: {connection_error_text(e)}", ''))
            findings.append(('Connection', ERROR, "the firewall stopped answering - the remaining checks weren't run",
                             "Check the firewall's management interface."))
            break
        except (PanError, requests.RequestException) as e:
            refused = isinstance(e, PanError) and fw.authenticated and (
                e.status_code == 403 or PERMISSION_ERROR.search(str(e)))
            findings.append((label, ERROR, f"could not read: {connection_error_text(e)}",
                             "The admin role needs permission for this command (XML API > Operational Requests, "
                             "Configuration or Log)." if refused else ''))
            if not fw.authenticated:
                findings.append(('Connection', ERROR, "the session ended - the remaining checks weren't run",
                                 "Retry Authentication, then run the health check again."))
                break
        except Exception as e:
            # A reply this tool didn't expect: say so, and carry on with the other checks
            findings.append((label, ERROR, f"tool error reading the reply - {type(e).__name__}: {e}",
                             "Report this, with the run log."))
    if ctx.clock_note:
        findings.append(('Clock', NOT_APPLICABLE, ctx.clock_note, ''))
    return findings


def overall_status(findings):
    """The firewall's result: its worst finding - FAIL, then ERROR (a check couldn't run), then WARN."""
    statuses = {status for _, status, _, _ in findings}
    return next((status for status in (FAIL, ERROR, WARN) if status in statuses), PASS)


def run_health_check(firewalls):
    """Palo Firewall Management option 7: every health check turned on in health_checks.yaml, on the
    chosen firewalls at once. A summary row per firewall, the details of each WARN, FAIL and ERROR with
    what to do about it, the HA pairs, and a CSV of every result. Nothing is changed on the firewalls."""
    health = load_health_checks()
    enabled = [label for key, label in HEALTH_CHECKS if health[f'{key}_enabled']]
    if not enabled:
        print("\nEvery health check is turned off - turn them on under Settings > Health Check Thresholds.")
        return
    selected = select_firewalls('Run the health check on', firewalls)
    if not selected:
        return
    stage('Health Check')
    off = [label for key, label in HEALTH_CHECKS if not health[f'{key}_enabled']]
    print(f"Running {len(enabled)} checks on {len(selected)} firewall(s)..."
          + (f"\nTurned off in {HEALTH_PATH.name}: {', '.join(off)}." if off else ''))
    results = parallel(lambda fw: run_health(fw, health), selected)
    for fw, findings in results.items():
        if isinstance(findings, Exception):
            results[fw] = [('Health Check', ERROR, f"tool error - {type(findings).__name__}: {findings}",
                            "Report this, with the run log.")]
    print()
    summary = []
    for fw in selected:
        findings = results[fw]
        attention = []
        for label, status, _, _ in sorted(findings, key=lambda f: STATUS_ORDER[f[1]]):
            if status in (FAIL, WARN, ERROR) and label not in attention:
                attention.append(label)
        summary.append({**ident(fw), 'Result': overall_status(findings),
                        'FAIL': str(sum(f[1] == FAIL for f in findings)),
                        'WARN': str(sum(f[1] == WARN for f in findings)),
                        'ERROR': str(sum(f[1] == ERROR for f in findings) or '-'),
                        'Needs attention': ', '.join(attention) or '-'})
    print_table(summary + skipped_rows(selected, 'Result'))
    flagged = [fw for fw in selected if overall_status(results[fw]) != PASS]
    if flagged:
        print("\nWhat failed, and what to do about it:")
    for fw in flagged:
        print(f"\n{fw} - {overall_status(results[fw])}")
        for label, status, detail, hint in sorted(results[fw], key=lambda f: STATUS_ORDER[f[1]]):
            if status not in (FAIL, WARN, ERROR):
                continue
            print(textwrap.fill(f"{label}: {detail}", 110, initial_indent=f"  {status:<5}  ",
                                subsequent_indent=' ' * 11))
            if hint:
                print(textwrap.fill(hint, 110, initial_indent=' ' * 11 + '> ', subsequent_indent=' ' * 13))
    if not flagged:
        print(f"\nEvery firewall passed all {len(enabled)} checks.")
    counts = {status: sum(overall_status(results[fw]) == status for fw in selected)
              for status in (PASS, WARN, ERROR, FAIL)}
    print(f"\nHealth check: {counts[FAIL]} FAIL, {counts[ERROR]} ERROR, {counts[WARN]} WARN, {counts[PASS]} PASS")
    print_skipped(selected)
    write_results('health check', [{**ident(fw), 'Check': label, 'Status': status, 'Detail': detail,
                                    'Remediation': hint}
                                   for fw in selected for label, status, detail, hint in results[fw]], selected)
    if not health['ha_enabled']:
        return
    pairs, notes = ha_pairs(selected, firewalls)
    if not pairs and not notes:
        return
    print_ha_pairs(pairs, selected, notes)


def config_snapshots(firewalls, config):
    while True:
        choice = menu('Config Snapshots', ['Create Config Snapshot', 'Download Recent Config Snapshot',
                                           'Download System State Backup'])
        if choice == '1':
            create_snapshots(firewalls)
        elif choice == '2':
            download_snapshots(firewalls, config)
        elif choice == '3':
            download_device_state(firewalls, config)
        else:
            return


# ---------------------------------------------------------------- deletes

def run_delete(fw, kind, **values):
    """Send one delete command and print the firewall's reply. Returns 'done', 'failed', or
    'timeout' when no reply came in time - the delete may still be running on the firewall."""
    try:
        result = fw.op(DELETE_COMMANDS[kind].format(**values), fw.check_timeout)
    except requests.ReadTimeout:
        print(f"{fw}: no reply within {fw.check_timeout[1]}s")
        return 'timeout'
    except (PanError, requests.RequestException) as e:
        print(f"{fw}: failed - {connection_error_text(e)}")
        return 'failed'
    message = ' '.join(''.join(result.itertext()).split()) if result is not None else ''
    print(f"{fw}: done" + (f" - {message}" if message else ''))
    return 'done'


def busy_now(fw):
    """Why nothing should be started on fw right now (a job queued or running, or it can't be
    checked), or None."""
    try:
        outcome = fw.running_jobs()
    except (PanError, requests.RequestException) as e:
        outcome = e
    return busy_check_text(fw, outcome)


def size_text(release):
    kb = release.get('size-kb', '')
    if kb.isdigit():
        return f"{int(kb) / 1024:.0f} MB"
    return f"{release['size']} MB" if release.get('size') else '-'


def run_deletes(plans, kind, selected=(), busy=None):
    """Delete each firewall's images (plans: {fw: [release]}), one at a time, then show a results
    table, which also lists the firewalls the Selection skipped and busy ({fw: reason}, the ones
    left out for a running job).

    Each delete waits until the firewall has no job queued or running, checked just before it's
    sent. A firewall stops there if a job is running, its session ends, or a delete gets no reply
    and the release list can't confirm it finished. The release lists from this session's update
    checks are marked as no longer downloaded, so a later install or download fetches them again."""
    results = []
    for fw, images in plans.items():
        deleted, stopped = 0, None
        for release in images:
            if not fw.authenticated:
                stopped = fw.auth_reason
                break
            name = release['version'] if kind == PANOS else release.get('filename') or release['version']
            if kind != PANOS and not release.get('filename'):
                print(f"{fw}: skipped {name} - the firewall didn't list its file name")
                continue
            busy_reason = busy_now(fw)
            if busy_reason:
                stopped = busy_reason
                break
            print(f"{fw}: deleting {name}...")
            status = run_delete(fw, kind, version=release['version'], filename=release.get('filename', ''))
            if status == 'timeout':
                # It may still be deleting: never send the next delete on top of it
                print(f"{fw}: checking whether {name} was deleted before going on...")
                try:
                    still_there = any(r['version'] == release['version'] and r.get('downloaded') == 'yes'
                                      for r in fw.cached_releases(kind))
                except (PanError, requests.RequestException) as e:
                    stopped = f"no reply to the delete of {name}, and the release list couldn't be read ({connection_error_text(e)})"
                    break
                if still_there:
                    stopped = f"no reply to the delete of {name}, and it's still listed - it may still be deleting"
                    break
                print(f"{fw}: {name} is gone - the delete finished")
                status = 'done'
            if status == 'done':
                deleted += 1
                for listed in fw.updates.get(kind) or []:
                    if listed['version'] == release['version']:
                        listed['downloaded'] = 'no'
        if stopped:
            print(f"{fw}: stopped - {stopped}. No more deletes sent to it.")
        result = (DONE if deleted == len(images) else EXPIRED if not fw.authenticated
                  else STOPPED if stopped else FAILED)
        results.append({**ident(fw), 'Deleted': f"{deleted} of {len(images)}",
                        'Result': result, 'Detail': stopped or '-'})
    results += [{**ident(fw), 'Deleted': '-', 'Result': SKIPPED, 'Detail': reason}
                for fw, reason in (busy or {}).items()]
    results = sorted(results, key=lambda row: int(row['#'])) + skipped_rows(selected, 'Result')
    print()
    print_table(results)
    write_results(f"{kind} delete", results, selected)


def leave_out_busy(plans):
    """Take the firewalls with a job queued or running (or that can't be checked) out of plans,
    saying so. Returns {fw: reason} for them."""
    busy = check_busy(list(plans))
    for fw, reason in busy.items():
        print(f"{fw}: skipped - {reason}")
        del plans[fw]
    return busy


def clear_content_cache(firewalls):
    selected = select_firewalls('Clear old content cache on', firewalls)
    if not selected:
        return
    stage('Clear Old Content Cache')
    plans = {fw: None for fw in selected}
    busy = leave_out_busy(plans)
    if not plans:
        print("Nothing to clear.")
        return
    if not confirm(f"Clear the old content cache on {len(plans)} firewall(s)?"):
        print("Nothing cleared.")
        return
    results = []
    for fw in plans:
        reason = busy_now(fw)
        if reason:
            print(f"{fw}: skipped - {reason}")
            results.append({**ident(fw), 'Result': SKIPPED, 'Detail': reason})
            continue
        print(f"{fw}: clearing the old content cache...")
        status = run_delete(fw, 'content-cache')
        results.append({**ident(fw),
                        'Result': (DONE if status == 'done' else EXPIRED if not fw.authenticated
                                   else UNKNOWN if status == 'timeout' else FAILED),
                        'Detail': 'no reply in time - it may still be clearing' if status == 'timeout' else '-'})
    results += [{**ident(fw), 'Result': SKIPPED, 'Detail': reason}
                for fw, reason in busy.items()]
    results = sorted(results, key=lambda row: int(row['#'])) + skipped_rows(selected, 'Result')
    print()
    print_table(results)
    write_results('Clear content cache', results, selected)


def deletable_images(fw, kind, releases=None):
    """Downloaded releases that aren't installed, newest first. For PAN-OS, also leaves out
    the base image of the installed version, which the firewall won't delete. releases is
    the firewall's release list, if it's already been read."""
    releases = fw.cached_releases(kind) if releases is None else releases
    current = next((r['version'] for r in releases if r.get('current') == 'yes'), None)
    base = '.'.join(current.split('.')[:2]) + '.0' if kind == PANOS and current else None
    return [r for r in releases
            if r.get('downloaded') == 'yes' and r.get('current') != 'yes' and r['version'] != base]


def delete_downloaded(firewalls, kind):
    """List the downloaded images of one kind on the chosen firewalls, merged by version, and
    delete the ones named by number on every chosen firewall that has them."""
    selected = select_firewalls(f"Delete downloaded {kind} images on", firewalls)
    if not selected:
        return
    stage(f"Downloaded {kind} images")
    images = {}
    for fw in selected:
        try:
            images[fw] = deletable_images(fw, kind)
        except (PanError, requests.RequestException) as e:
            print(f"{fw}: could not list images: {connection_error_text(e)}")
    merged = merge_releases(images)
    if not merged:
        print("No downloaded images apart from the installed ones.")
        return

    numbered = dict(enumerate(merged, 1))
    rows = []
    for number, (version, summary) in numbered.items():
        # Marked previous: the version a revert goes back to
        previous = sum(any(r['version'] == version and r.get('previous') == 'yes' for r in releases)
                       for releases in images.values())
        rows.append({
            '#': str(number),
            'Version': version,
            'File': summary['release'].get('filename') or '-',
            'Released': short_date(summary['release'].get('released-on')),
            'Size': size_text(summary['release']),
            'Downloaded on': f"{summary['listed']} of {len(images)}",
            'Note': f"previous version on {previous}, used to revert" if previous else '-',
        })
    print_table(rows)

    print()
    chosen = {version for version, _ in pick('Delete', numbered, explicit=True)}
    if not chosen:
        print("Nothing deleted.")
        return
    plans = {fw: [r for r in releases if r['version'] in chosen] for fw, releases in images.items()}
    plans = {fw: releases for fw, releases in plans.items() if releases}
    print()
    busy = leave_out_busy(plans)
    if not plans:
        print("Nothing to delete.")
        return
    print("\nAbout to delete:")
    for fw, releases in plans.items():
        print(f"  {fw}: {', '.join(r.get('filename') or r['version'] for r in releases)}")
    count = sum(len(releases) for releases in plans.values())
    if not confirm(f"Delete {count} file(s) on {len(plans)} firewall(s)?"):
        print("Nothing deleted.")
        return
    run_deletes(plans, kind, selected, busy)


# ---------------------------------------------------------------- menus

class Selection(list):
    """The firewalls picked for an action, plus .skipped: the ones left out because they aren't
    authenticated, so the action can report them."""

    def __init__(self, picked, skipped=()):
        super().__init__(picked)
        self.skipped = list(skipped)


def skipped_text(fw):
    return f"SKIPPED - not authenticated ({fw.auth_result or 'not tried'})"


def print_skipped(firewalls):
    """One line under a listing table naming the firewalls it skipped."""
    skipped = getattr(firewalls, 'skipped', [])
    if skipped:
        print(f"\nSkipped - not authenticated: {', '.join(str(fw) for fw in skipped)}")


def skipped_rows(firewalls, column):
    """Table rows for the firewalls an action skipped, with the reason in column - or, for a results
    table (column 'Result'), SKIPPED with the reason under Detail."""
    if column == 'Result':
        return [{**ident(fw), 'Result': SKIPPED, 'Detail': f"not authenticated ({fw.auth_result or 'not tried'})"}
                for fw in getattr(firewalls, 'skipped', [])]
    return [{**ident(fw), column: skipped_text(fw)}
            for fw in getattr(firewalls, 'skipped', [])]


def select_firewalls(label, firewalls, need_key=True, blank_means_all=True):
    """List every firewall by number and let the user pick the ones to act on.

    Only firewalls with an API key can be picked - or, when need_key is False (retrying
    authentication), only those without one. Firewalls without a key are always reported as
    skipped, with their reason, and returned in .skipped. Skips the question when just one can
    be picked.
    """
    choices = {fw.number: fw for fw in firewalls if fw.authenticated == need_key}
    unusable = [fw for fw in firewalls if fw.number not in choices]
    skipped = unusable if need_key else []
    if skipped:
        print(f"\nSkipped - not authenticated ({len(skipped)}):")
        for fw in skipped:
            print(f"  {fw}: {fw.auth_result or 'not tried'} - {fw.auth_reason or 'no API key'}")
    if len(choices) <= 1:
        return Selection(choices.values(), skipped)
    reason = 'not authenticated' if need_key else 'already authenticated'
    blocked = {fw.number: reason for fw in unusable}
    print()
    for fw in firewalls:
        print(f"  {fw}" + (f"  ({reason})" if fw.number in blocked else ''))
    return Selection(pick(label, choices, blocked, blank_means_all), skipped)


def retry_authentication(firewalls, config):
    """Authenticate the chosen firewalls that have no key (failed, skipped or expired) again."""
    selected = select_firewalls('Retry authentication for', firewalls, need_key=False)
    if selected:
        authenticate(selected, config)
        review_inventory(firewalls)


# ---------------------------------------------------------------- log search

# Search Logs (Palo Firewall Management option 6): menu label -> the XML API's log-type
LOG_TYPES = [
    ('Traffic', 'traffic'), ('Threat', 'threat'), ('URL Filtering', 'url'), ('WildFire', 'wildfire'),
    ('Data Filtering', 'data'), ('Config', 'config'), ('System', 'system'), ('HIP Match', 'hipmatch'),
    ('GlobalProtect', 'globalprotect'), ('User-ID', 'userid'), ('Authentication', 'auth'),
    ('Decryption', 'decryption'), ('IP-Tag', 'iptag'),
]
LOG_DEFAULT_COUNT = 20
LOG_MAX_COUNT = 5000
# Seconds between checks on a log search job (it usually finishes in a few seconds)
LOG_POLL_INTERVAL = 2
# Summary columns: heading -> log field. Columns no entry has are left out (print_table), so each log
# type shows the ones it has; every field goes in the CSV.
LOG_COLUMNS = [('Source', 'src'), ('Src Zone', 'from'), ('Src Port', 'sport'), ('Destination', 'dst'),
               ('Dst Zone', 'to'), ('Dst Port', 'dport'), ('App', 'app'), ('Action', 'action'), ('Rule', 'rule')]
LOG_EXTRA_COLUMNS = {
    'threat': [('Threat', 'threatid'), ('Severity', 'severity')],
    'url': [('URL', 'misc'), ('Category', 'category')],
    'wildfire': [('File', 'misc'), ('Verdict', 'category')],
    'data': [('File', 'misc')],
    'system': [('Severity', 'severity'), ('Event', 'eventid'), ('Description', 'opaque')],
    'config': [('Admin', 'admin'), ('Command', 'cmd'), ('Path', 'path'), ('Result', 'result')],
    'globalprotect': [('User', 'srcuser'), ('Event', 'eventid'), ('Status', 'status')],
    'userid': [('User', 'user'), ('IP', 'ip'), ('Source Type', 'datasourcetype')],
    'auth': [('User', 'user'), ('Event', 'event'), ('Auth Profile', 'authpolicy')],
    'hipmatch': [('User', 'srcuser'), ('Machine', 'machinename'), ('HIP', 'matchname')],
    'iptag': [('Tag', 'tag_name'), ('IP', 'ip'), ('Event', 'event_id')],
}
LOG_CELL_WIDTH = 60
# Shown above the Query prompt: the web UI filter syntax for that log type
LOG_QUERY_EXAMPLES = {
    'traffic': ["( addr.src in 10.1.1.5 ) and ( port.dst eq 443 ) and ( action eq deny )"],
    'threat': ["( severity geq high ) and ( subtype eq vulnerability )"],
    'url': ["( url contains 'example.com' ) and ( action eq block-url )"],
    'wildfire': ["( category eq malicious )"],
    'data': ["( addr.src in 10.1.1.5 ) and ( action eq deny )"],
    'config': ["( admin eq jsmith ) and ( cmd eq set )", "( path contains 'rulebase' )"],
    'system': ["( severity geq high )", "( subtype eq ha )", "( description contains 'commit' )"],
    'hipmatch': ["( machinename eq LAPTOP01 )", "( matchname eq 'Corp-Compliant' )"],
    'globalprotect': ["( eventid eq 'portal-auth' ) and ( status eq 'failure' )", "( eventid eq gateway-auth )"],
    'userid': ["( user eq 'corp\\jdoe' )", "( ip eq 10.1.1.5 )"],
    'auth': ["( user eq 'corp\\jdoe' )", "( authpolicy eq 'MFA-Policy' )"],
    'decryption': ["( sni contains 'example.com' )", "( addr.dst in 10.1.1.5 )"],
    'iptag': ["( tag_name eq quarantine )", "( ip eq 10.1.1.5 )"],
}
LOG_TIME_EXAMPLE = "( receive_time geq '2026/11/14 08:00:00' )"
# The last query per log type this run, offered as the default next time
LAST_LOG_QUERY = {}


def log_time(entry):
    """When the firewall logged it ('2026/11/15 09:12:44'), which sorts as text."""
    return entry.get('time_generated') or entry.get('receive_time') or ''


def fetch_logs(fw, log_type, query, count, timeout):
    """Run a log search job on fw and return its entries (dicts of field -> text), newest first. The
    job is stopped (action=finish) if it doesn't finish within timeout seconds or anything fails."""
    data = {'type': 'log', 'log-type': log_type, 'nlogs': str(count), 'dir': 'backward'}
    if query:
        data['query'] = query
    job = fw.post(data).findtext('result/job')
    if not job:
        raise PanError("the firewall didn't return a log search job")
    deadline = time.monotonic() + timeout
    try:
        while True:
            result = fw.post({'type': 'log', 'action': 'get', 'job-id': job}).find('result')
            if result is not None and result.findtext('job/status') == 'FIN':
                job = None
                logs = result.find('log/logs')
                return [] if logs is None else [
                    {child.tag: ' '.join(''.join(child.itertext()).split()) for child in entry}
                    for entry in logs.findall('entry')]
            if time.monotonic() > deadline:
                raise PanError(f"the search didn't finish within check_timeout ({timeout}s)")
            time.sleep(LOG_POLL_INTERVAL)
    finally:
        if job:
            try:
                fw.post({'type': 'log', 'action': 'finish', 'job-id': job})
            except Exception:
                pass


def log_failure_text(error):
    text = connection_error_text(error) if isinstance(error, requests.RequestException) else str(error)
    if isinstance(error, PanError) and (error.status_code == 403 or re.search(r'privilege|permission|unauthori',
                                                                               text, re.IGNORECASE)):
        text += " - the admin role needs XML API > Log permission"
    return text


def log_rows(entries, log_type):
    """Summary table rows: time, device, then LOG_COLUMNS and the log type's own columns."""
    columns = LOG_COLUMNS + LOG_EXTRA_COLUMNS.get(log_type, [])

    def cell(value):
        value = value or '-'
        return value if len(value) <= LOG_CELL_WIDTH else value[:LOG_CELL_WIDTH - 3] + '...'
    return [{'Time': log_time(e) or '-', 'Device': e['_device'],
             **{heading: cell(e.get(name)) for heading, name in columns}} for e in entries]


def save_log_csv(entries, log_type, config):
    """Every field of every entry to <download_folder>\\<date>_<time>_<log type>_logs.csv."""
    import csv
    folder = config_folder(config['download_folder'])
    fields = ['device', 'device_address']
    for entry in entries:
        fields += [k for k in entry if not k.startswith('_') and k not in fields]
    try:
        folder.mkdir(parents=True, exist_ok=True)
        path = free_path(folder, f"{datetime.datetime.now():%Y-%m-%d_%H%M%S}_{log_type}_logs.csv")
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fields, restval='', extrasaction='ignore')
            writer.writeheader()
            for entry in entries:
                writer.writerow({**entry, 'device': entry['_device'], 'device_address': entry['_address']})
    except OSError as e:
        print(f"Could not save the CSV in {folder}: {e.strerror}")
        return
    print(f"Saved {len(entries)} entries to {path}")
    log_only(f"Log search results saved to {path}")


def search_logs(firewalls, config):
    """Palo Firewall Management option 6: search one log type on the chosen firewalls with a query in the web
    UI's filter syntax (sent as it is, in the POST body). The entries from every firewall are merged
    newest first by their own timestamps, shown as a summary table and offered as a CSV with every
    field. Only a one-line summary goes in the run log."""
    while True:
        choice = menu('Search Logs', [label for label, _ in LOG_TYPES])
        if choice == '0':
            return
        label, log_type = LOG_TYPES[int(choice) - 1]
        selected = select_firewalls(f"Search {label} logs on", firewalls)
        if not selected:
            continue
        stage(f"Search {label} Logs")
        print(f"Query: the web UI's {label} log filter syntax, e.g.")
        for example in LOG_QUERY_EXAMPLES.get(log_type, []) + [LOG_TIME_EXAMPLE]:
            print(f"         {example}")
        print("       Blank searches everything.")
        print(EDIT_HINT)
        query = edit_value('Query', LAST_LOG_QUERY.get(log_type, ''), '')
        if query is CANCEL:
            print("Cancelled.")
            continue
        count = edit_value('Entries per firewall', LOG_DEFAULT_COUNT, LOG_DEFAULT_COUNT,
                           Setting('nlogs', 'number', LOG_DEFAULT_COUNT, '', 1, LOG_MAX_COUNT).parse)
        if count is CANCEL:
            print("Cancelled.")
            continue
        LAST_LOG_QUERY[log_type] = query
        print(f"\nSearching {label} logs on {len(selected)} firewall(s)...")
        results = parallel(lambda fw: fetch_logs(fw, log_type, query, count, config['check_timeout']), selected)
        entries, failed = [], []
        for fw, result in results.items():
            if isinstance(result, Exception):
                failed.append((fw, log_failure_text(result)))
                continue
            for entry in result:
                entry['_device'], entry['_address'] = fw.hostname or fw.name, fw.name
            entries += result
        # Newest first across every firewall; Python's sort keeps each firewall's own order for ties
        entries.sort(key=log_time, reverse=True)
        print_skipped(selected)
        for fw, reason in failed:
            print(f"  {fw}: FAILED - {reason}")
        summary = (f"{label} log search on {len(selected)} firewall(s), query {query or '(none)'!r}, "
                   f"{count} per firewall: {len(entries)} entries" + (f", {len(failed)} failed" if failed else ''))
        log_only(summary)
        if not entries:
            print(f"\nNo {label} log entries found.")
            continue
        print()
        with screen_only():
            print_table(log_rows(entries, log_type))
        print(f"\n{len(entries)} entries, newest first, merged by each firewall's own clock"
              + (" - firewalls whose clocks differ will interleave out of step." if len(selected) > 1 else '.'))
        if confirm(f"Save all {len(entries)} entries, with every field, to a CSV in {config['download_folder']}?"):
            save_log_csv(entries, log_type, config)


# ---------------------------------------------------------------- SSH

class AskpassServer:
    """Hands the password to one ssh session, once, over a local named pipe.

    ssh asks for a password by running the program named in SSH_ASKPASS: this tool's EXE, started
    again in askpass mode (askpass_main). That copy connects to the pipe, proves it holds this
    session's random key, and gets the password. The pipe then closes, so any later password prompt
    (a wrong password, or an MFA code) is left to you. The password never goes on a command line, in
    an environment variable or on disk, and Windows limits the pipe to your own account.
    """

    def __init__(self, password, target=''):
        from multiprocessing.connection import Listener
        self.password = password
        # 'user@host' of the firewall: askpass_main only fetches the password for a prompt naming it,
        # so a JumpHost's prompts never get it
        self.target = target
        self.key = secrets.token_bytes(32)
        self.address = rf"\\.\pipe\net-dev-cli-askpass-{secrets.token_hex(16)}"
        self.listener = Listener(self.address, family='AF_PIPE', authkey=self.key)
        self.done = threading.Event()
        self.served = False
        self.thread = threading.Thread(target=self.serve, name='ssh askpass', daemon=True)

    @property
    def env_value(self):
        """Where askpass_main finds the pipe, the key it proves itself with, and the firewall's
        user@host it may fill in for (not the password)."""
        return f"{self.address}|{self.key.hex()}|{self.target}"

    def __enter__(self):
        self.thread.start()
        return self

    def serve(self):
        from multiprocessing import AuthenticationError
        failures = 0
        try:
            while not self.done.is_set() and failures < 20:
                try:
                    conn = self.listener.accept()
                except (AuthenticationError, EOFError, OSError):
                    # A caller without the key, or one that hung up: keep waiting for ssh's
                    failures += 1
                    continue
                with conn:
                    password = self.password
                    if password is not None and not self.done.is_set():
                        conn.send_bytes(password.encode('utf-8'))
                        self.served = True
                return
        finally:
            self.password = None
            self.listener.close()

    def __exit__(self, *exc):
        self.done.set()
        self.password = None
        if self.thread.is_alive():
            # accept() can't be interrupted, so connect once to end it; it sends nothing once done
            from multiprocessing.connection import Client
            try:
                Client(self.address, family='AF_PIPE', authkey=self.key).close()
            except Exception:
                pass
            self.thread.join(timeout=5)


def fetch_password(value):
    """Askpass mode: the password from AskpassServer (value is ASKPASS_ENV), or None once it has
    been handed over or the session is over."""
    from multiprocessing import AuthenticationError
    from multiprocessing.connection import Client
    address, _, rest = value.partition('|')
    key = rest.partition('|')[0]
    try:
        with Client(address, family='AF_PIPE', authkey=bytes.fromhex(key)) as conn:
            return conn.recv_bytes().decode('utf-8')
    except (OSError, EOFError, ValueError, AuthenticationError):
        return None


def console_answer(prompt, echo):
    """Askpass mode: ask on the console itself, since ssh reads this program's output for the answer."""
    if not echo:
        # On Windows getpass reads and writes the console directly
        return getpass.getpass(prompt)
    with open('CONOUT$', 'w') as out, open('CONIN$') as inp:
        out.write(prompt)
        out.flush()
        line = inp.readline()
    if not line:
        raise EOFError
    return line.rstrip('\r\n')


def prompt_names(prompt, target):
    """Whether an ssh prompt is the firewall's own password prompt for target (['user@host'], from
    ASKPASS_ENV). It has to start with target, the way ssh writes those prompts: "user@host's password: "
    (a password login) or "(user@host) ..." (keyboard-interactive, OpenSSH 8.5+). A JumpHost can put any
    text in its own keyboard-interactive prompt, but ssh starts that prompt with the JumpHost's
    (user@host) - so a prompt that only mentions the firewall further on never gets the password. The
    name has to be followed by "'s password" or ")", so admin@10.1.0.2 doesn't match admin@10.1.0.25."""
    target = target[0] if target else ''
    name = re.escape(target)
    return bool(target) and bool(re.match(rf"(?:{name}'s password|\({name}\))", prompt, re.IGNORECASE))


def askpass_main(args):
    """Askpass mode: this tool started by ssh (SSH_ASKPASS) to answer one prompt, passed as the
    argument; the answer goes to ssh on stdout. Returns the exit code (non-zero cancels the prompt).

    A password prompt naming the firewall ('admin@10.1.0.2's password:' or '(admin@10.1.0.2)
    Password:') gets the session's password from AskpassServer, once. Anything else - a JumpHost's
    password or key passphrase, the host key to confirm, a second password prompt, an MFA code - is
    asked on the console.
    """
    prompt = ' '.join(args)
    try:
        confirming = bool(SSH_CONFIRM_PROMPT.search(prompt))
        value = os.environ.get(ASKPASS_ENV, '')
        answer = None
        if SSH_PASSWORD_PROMPT.search(prompt) and not confirming and prompt_names(prompt, value.split('|')[2:3]):
            answer = fetch_password(value)
        if answer is None:
            answer = console_answer(prompt, echo=confirming)
        sys.stdout.buffer.write(answer.encode('utf-8') + b'\n')
        sys.stdout.flush()
        return 0
    except BaseException:
        # Ctrl+C, no console, or anything unexpected: ssh treats it as no answer
        return 1


def ssh_version():
    """(major, minor) of the built-in OpenSSH client, or None if it can't be read."""
    try:
        result = subprocess.run([str(SSH_CLIENT), '-V'], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = SSH_VERSION.search(result.stderr + result.stdout)
    return (int(match[1]), int(match[2])) if match else None


def ssh_fill_blocker(version):
    """Why the password can't be filled in for any firewall, or None if it can."""
    if not FROZEN:
        return "running from source, and ssh can only take a password from a program - the EXE fills it in"
    needed = '.'.join(map(str, SSH_ASKPASS_VERSION))
    if not version:
        return f"the OpenSSH client's version couldn't be read, and filling in needs {needed} or later"
    if version < SSH_ASKPASS_VERSION:
        return (f"this OpenSSH client ({version[0]}.{version[1]}) is older than {needed}, which the tool "
                f"needs to fill in the password safely")
    return None


def ssh_host(fw):
    """The address the API connects to, without its HTTPS port."""
    return fw.host.rsplit(':', 1)[0] if fw.host.count(':') == 1 else fw.host


def connect_ssh(firewalls, config):
    """Palo Firewall Management option 8: an SSH session to one firewall with Windows' built-in OpenSSH client,
    in this window, as the username from Authentication, directly or through a JumpHost. The
    password is filled in for a firewall that accepted it (CREDENTIALS, AskpassServer). Back at the
    Palo Firewall Management menu when the session ends.

    Host keys are checked as ssh always does (your known_hosts); the tool never turns that off.
    """
    stage('Connect via SSH')
    if not SSH_CLIENT.exists():
        print(f"Windows' OpenSSH client isn't installed ({SSH_CLIENT} not found). Add 'OpenSSH Client' "
              f"under Settings > System > Optional features, then try again.")
        return
    blocker = ssh_fill_blocker(ssh_version())
    if blocker:
        print(f"ssh will ask for the password: {blocker}.")
    print()
    for fw in firewalls:
        if blocker:
            note = ''
        elif CREDENTIALS.fills(fw):
            note = '  (password filled in)'
        else:
            note = f"  (you type the password - not authenticated: {fw.auth_result or 'not tried'})"
        print(f"  {fw}{note}")
    chosen = pick('Connect to', {fw.number: fw for fw in firewalls}, single=True)
    if not chosen:
        return
    fw = chosen[0]
    username = CREDENTIALS.username or prompt('Username', getpass.getuser())
    jump = None
    if config['jump_hosts'] and confirm("Use a JumpHost?"):
        jump = pick_jump_host(config, 'JumpHost')
        if jump is None:
            print("No JumpHost picked - nothing started.")
            return
        try:
            jump_route(config['jump_hosts'], jump, config[JUMP_CHAINING.key])
        except ValueError as e:
            print(f"That JumpHost can't be used: {e}. Fix it under Settings > Application Settings > JumpHosts.")
            return
    run_ssh(fw, username, fill=not blocker and CREDENTIALS.fills(fw), config=config, jump=jump)


def run_ssh(fw, username, fill, config=None, jump=None):
    """ssh to fw, through JumpHost number jump if given (ssh -F <the JumpHosts> -J <its Host>)."""
    host = ssh_host(fw)
    route = ''
    if jump:
        hosts = config['jump_hosts']
        route = route_text(hosts, jump_route(hosts, jump, config[JUMP_CHAINING.key]), str(fw))
    print(f"\nOpening SSH to {fw} as {username}" + (f" (route: {route})" if route else '') + ". "
          + ("The password is filled in" if fill else "Type the password when ssh asks")
          + " - approve the MFA push if one arrives.")
    if jump:
        print("Type anything a JumpHost asks for (its password or key passphrase) yourself - the firewall "
              "password is only filled in at the firewall's own prompt.")
    print("If ssh asks you to confirm a host key, check the fingerprint before answering yes.")
    print(f"Type exit on the firewall to come back to {MANAGEMENT_MENU}.\n")
    log_only(f"SSH session to {fw} ({host}) as {username}" + (f" via {route}" if route else '') + " started"
             + (' - password filled in' if fill else ''))
    env = ssh_env()
    command = [str(SSH_CLIENT), '-l', username, host]
    code = None
    with ACTIVITY.hold(), contextlib.ExitStack() as stack:
        if jump:
            try:
                path = stack.enter_context(ssh_config_file(config))
            except (OSError, ValueError) as e:
                print(f"Could not write the JumpHost settings for ssh: {e}")
                return
            command = [str(SSH_CLIENT), '-F', path, '-J', config['jump_hosts'][jump]['host'], '-l', username, host]
        if fill:
            server = stack.enter_context(AskpassServer(CREDENTIALS.password, f"{username}@{host}"))
            env.update({'SSH_ASKPASS': sys.executable, 'SSH_ASKPASS_REQUIRE': 'force',
                        ASKPASS_ENV: server.env_value})
        sys.stdout.flush()
        # Ctrl+C belongs to ssh (and the firewall's CLI) while the session runs, not to this tool
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            code = subprocess.run(command, env=env).returncode
        except OSError as e:
            print(f"Could not start ssh: {e.strerror or e}")
        finally:
            signal.signal(signal.SIGINT, previous)
    if code is None:
        return
    log_only(f"SSH session to {fw} ended (ssh exit code {code})")
    if code == 255:
        print(f"\nssh couldn't connect or log in to {fw} - its message is above.")
    else:
        print(f"\nSSH session to {fw} ended.")


MANAGEMENT_MENU = 'Palo Firewall Management'


def command_list(firewalls, config, keepalive=None):
    """The Palo Firewall Management menu (Main Menu > Manage Devices) for the connected firewalls.
    0 goes back to the Main Menu, still connected."""
    announced, paused_announced = set(), set()
    while True:
        restarted = keepalive.check() if keepalive else None
        if restarted:
            print(f"\n{restarted}")
        # Say once when a firewall's session has ended, rather than leaving it to the next failure.
        # A firewall that's re-authenticated is dropped from announced, so a later expiry shows too.
        announced &= {fw for fw in firewalls if fw.auth_result == EXPIRED}
        ended = [fw for fw in firewalls if fw.auth_result == EXPIRED and fw not in announced]
        if ended:
            print(f"\nSession ended on {', '.join(str(fw) for fw in ended)} - "
                  f"re-authenticate with Retry Authentication.")
            announced.update(ended)
        # Same for firewalls whose keep-alive polls stopped (the key is still held)
        paused = {(fw, fw.keepalive_stopped) for fw in firewalls if fw.authenticated and fw.keepalive_stopped}
        paused_announced &= paused
        for fw, reason in sorted(paused - paused_announced, key=lambda item: item[0].number):
            print(f"\nKeep-alive stopped for {fw}: {reason}. It starts again after the next action "
                  f"that reaches it.")
        paused_announced |= paused
        # Counted each time the menu is shown, so it follows failures, expiries and retries
        pending = sum(not fw.authenticated for fw in firewalls)
        choice = menu(MANAGEMENT_MENU, [
            'List Currently Installed Content Versions',
            'List Currently Installed PAN-OS Version',
            'Manage Content Updates',
            'Manage PAN-OS Updates',
            'Config Snapshots',
            'Search Logs',
            'Run Health Check',
            'Connect via SSH',
            f"Retry Authentication ({pending} firewall(s) not authenticated)" if pending else None,
        ], zero='Main Menu')
        if choice in ('1', '2'):
            selected = select_firewalls('List for', firewalls)
            if selected:
                (show_content_versions if choice == '1' else show_panos_versions)(selected)
        elif choice == '3':
            manage_content_updates(firewalls)
        elif choice == '4':
            manage_panos_updates(firewalls, config)
        elif choice == '5':
            config_snapshots(firewalls, config)
        elif choice == '6':
            search_logs(firewalls, config)
        elif choice == '7':
            run_health_check(firewalls)
        elif choice == '8':
            connect_ssh(firewalls, config)
        elif choice == '9':
            retry_authentication(firewalls, config)
        else:
            return


class Connection:
    """The firewalls connected to, from Connect to Device(s) until Disconnect. Going back to the Main
    Menu leaves them connected (and kept alive); Manage Devices returns to Palo Firewall Management."""

    def __init__(self):
        self.firewalls = []
        self.keepalive = None
        self.lock = threading.Lock()

    @property
    def connected(self):
        return sum(fw.authenticated for fw in self.firewalls)


CONNECTION = Connection()
# Logouts sent at once by Disconnect
LOGOUT_PARALLEL = 32
# Closing the console window: Windows ends the process about 5 seconds later, so each logout gets
# this many seconds, after waiting at most CLOSE_LOCK_WAIT for a request already in flight
CLOSE_LOGOUT_TIMEOUT = 3
CLOSE_LOCK_WAIT = 1


def disconnect(reason, timeout=None, wait=None, quiet=False):
    """Disconnect: stop the keep-alive, log out of every firewall that holds a key (Firewall.logout,
    all at once), clear the keys and the password, and report each firewall. The same operation
    whatever starts it - the Disconnect option, Exit, Ctrl+C, an error, the idle timeout, or
    closing the window (quiet: the console may be gone, so the report goes to the run log only).
    Does nothing when nothing is connected; safe to call from any thread."""
    from concurrent.futures import ThreadPoolExecutor
    with CONNECTION.lock:
        firewalls, keepalive = CONNECTION.firewalls, CONNECTION.keepalive
        CONNECTION.firewalls, CONNECTION.keepalive = [], None
    if not firewalls:
        CREDENTIALS.clear()
        return
    say = log_only if quiet else print
    # Stopped first: a poll after the logout would log the admin back in
    if keepalive:
        keepalive.stop()
    holding = [fw for fw in firewalls if fw.authenticated]
    if holding:
        with contextlib.suppress(OSError):
            say(f"\nDisconnecting ({reason}) - logging out of {len(holding)} firewall(s)...")
        with ThreadPoolExecutor(max_workers=min(len(holding), LOGOUT_PARALLEL)) as pool:
            futures = {fw: pool.submit(fw.logout, timeout, wait) for fw in holding}
        outcomes = {fw: future.exception() for fw, future in futures.items()}
    else:
        outcomes = {}
    CREDENTIALS.clear()
    for fw in firewalls:
        fw.close()
    rows = []
    for fw in firewalls:
        if fw in outcomes:
            error = outcomes[fw]
            if error is None:
                result, detail = 'Logged out', f"admin sessions for {fw.username} ended"
            else:
                text = connection_error_text(error) if isinstance(error, requests.RequestException) else str(error)
                result, detail = FAIL, f"{text} - the session ends at the firewall's idle timeout"
        elif fw.username:
            result, detail = '-', f"no key held ({fw.auth_reason or 'session already ended'})"
        else:
            continue
        rows.append({**ident(fw), 'Logout': result, 'Detail': detail})
    try:
        if rows:
            if quiet:
                for row in rows:
                    log_only(f"  #{row['#']} {row['Firewall']}: {row['Logout']} - {row['Detail']}")
            else:
                print()
                print_table(rows)
        say("Disconnected - API keys and password cleared from memory.")
    except OSError:
        pass


def connect(config):
    """Main Menu option 1: pick firewalls and authenticate them, then back to the Main Menu (Manage
    Devices opens their menu). Firewalls already connected stay connected and the new ones join
    them; one already in the session isn't added twice (one without a key is authenticated again)."""
    targets = choose_targets(config)
    if not targets:
        return
    existing = {fw.host.lower(): fw for fw in CONNECTION.firewalls}
    new, again = [], []
    for target in targets:
        fw = existing.get(target['host'].lower())
        if fw is None:
            new.append(Firewall(target, config))
        elif fw.authenticated:
            print(f"{fw} is already connected.")
        elif fw not in again:
            again.append(fw)
    # Numbered on from the firewalls already connected, so every number in the session is unique
    start = max((fw.number for fw in CONNECTION.firewalls), default=0)
    for offset, fw in enumerate(new, 1):
        fw.number = start + offset
    if new or again:
        if not CONNECTION.firewalls:
            ACTIVITY.disconnected.clear()
            ACTIVITY.touch()
        CONNECTION.firewalls.extend(new)
        if CONNECTION.keepalive is None:
            # Running from the start, so each firewall is kept alive as soon as its key works, while
            # the rest are still being authenticated. It polls CONNECTION.firewalls, new ones included.
            CONNECTION.keepalive = KeepAlive(CONNECTION.firewalls, config['keepalive_interval'],
                                             config['app_idle_timeout'] * 60)
            CONNECTION.keepalive.start()
        try:
            authenticate(again + new, config)
            review_inventory(CONNECTION.firewalls)
        except IdleDisconnect:
            print("Disconnected by the application idle timeout - back to the Main Menu.")
            ACTIVITY.disconnected.clear()
            return
        if not CONNECTION.connected:
            print("\nNo firewall authenticated.")
            disconnect('no firewall authenticated')
            return
    print(f"\n{CONNECTION.connected} firewall(s) connected - Manage Devices opens {MANAGEMENT_MENU}.")


def manage_devices(config):
    """Main Menu option 2 (shown while connected): Palo Firewall Management for the connected firewalls."""
    if not CONNECTION.firewalls:
        print("Nothing is connected - use Connect to Device(s).")
        return
    try:
        command_list(CONNECTION.firewalls, config, CONNECTION.keepalive)
    except IdleDisconnect:
        print("Disconnected by the application idle timeout - back to the Main Menu.")
        ACTIVITY.disconnected.clear()


def watch_console_close():
    """Windows: closing the console window (or signing out, or shutting down) runs Disconnect before
    the process ends. Windows allows about 5 seconds, so each logout gets CLOSE_LOGOUT_TIMEOUT."""
    if os.name != 'nt':
        return
    import ctypes
    from ctypes import wintypes
    close_events = {2, 5, 6}  # CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    def handler(event):
        if event not in close_events:
            return False  # Ctrl+C and Ctrl+Break: Python's own handler (KeyboardInterrupt)
        try:
            disconnect('window closed', CLOSE_LOGOUT_TIMEOUT, CLOSE_LOCK_WAIT, quiet=True)
        except BaseException:
            pass
        return False
    global _CLOSE_HANDLER
    # Kept referenced for as long as the tool runs
    _CLOSE_HANDLER = handler
    ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)


_CLOSE_HANDLER = None


def device_list():
    """The device database in View Devices order (by hostname, else IP). Its numbers, from 1, are the
    index numbers the Target prompt takes."""
    return sorted(DEVICES.rows(), key=lambda r: (r.get('hostname') or r.get('ip') or '').lower())


def device_table(rows):
    """Devices (in device_list order) as a table: one row per firewall, numbered from 1."""
    def peer(row):
        name = row.get('ha_peer_hostname') or row.get('ha_peer_mgmt_ip') or row.get('ha_peer_serial')
        return name or '-'
    return [{
        '#': str(number),
        'Serial': row.get('serial') or '(not connected)',
        'Hostname': row.get('hostname') or '-',
        'IP': row.get('ip') or '-',
        'Model': row.get('model') or '-',
        'PAN-OS': row.get('sw_version') or '-',
        'HA': (state_text(row.get('ha_state')) if row.get('ha_enabled') == 'yes'
               else 'Standalone' if row.get('ha_enabled') == 'no' else '-'),
        'HA Peer': peer(row),
        'Last seen': row.get('last_seen') or '-',
    } for number, row in enumerate(rows, 1)]


def ask_data_path(config, action):
    """Ask which data file to load or write, offering the current one (data_path). None if no
    file is named."""
    text = prompt(f"Data file to {action}", str(data_path(config) or '')).strip().strip('"')
    return config_folder(text) if text else None


def load_data_file(config, path, missing_note=True):
    """Read a data file into the device database, replacing what it held, and say so in one line.
    The file becomes this run's data file (DEVICES.source). Returns the number of firewalls read;
    the device database is left as it was if the file can't be read."""
    if not path.exists():
        if missing_note:
            print(f"No data file at {path} yet. Write Local Data File creates it - empty, as a template, "
                  f"or with the firewalls you've connected to.")
        return 0
    try:
        rows, _ = read_data_rows(path)
    except (OSError, UnicodeDecodeError) as e:
        print(f"Could not read {path}: {getattr(e, 'strerror', None) or e}")
        return 0
    usable = [r for r in rows if r.get('ip') or r.get('hostname')]
    unusable = len(rows) - len(usable)
    DEVICES.clear()
    for row in usable:
        DEVICES.add_row(row)
    DEVICES.source = path
    print(f"Loaded {len(usable)} firewall(s) from {path}"
          + (f" ({unusable} line(s) left out - no IP or hostname)" if unusable else '')
          + f". Known devices: {len(DEVICES)}.")
    return len(usable)


def load_data_menu(config):
    """Main Menu option 4: ask for the data file (the current one by default) and load it in place of
    the device database. Asks first if connections have added devices that aren't written yet."""
    stage('Load Local Data File')
    path = ask_data_path(config, 'load')
    if path is None:
        return
    if not path.exists():
        print(f"No data file at {path}. Nothing loaded.")
        return
    if DEVICES.changed and len(DEVICES):
        print(f"The device database holds {len(DEVICES)} device(s), with changes from connections this run "
              f"that haven't been written to a data file. Loading replaces them.")
        if not confirm(f"Load {path.name} anyway?"):
            print("Nothing loaded.")
            return
    load_data_file(config, path)


def view_devices():
    """Main Menu option 6 (shown once the device database holds devices): the known devices, numbered.
    The Target prompt takes one of these numbers."""
    stage('View Devices')
    devices = device_list()
    if not devices:
        print("No known devices yet - Load Local Data File, or connect to some firewalls.")
        return
    print_table(device_table(devices))
    if DEVICES.unkeyed:
        print(f"\n{len(DEVICES.unkeyed)} device(s) have no serial number yet - it's added once the tool connects to them.")
    print(f"\nConnect to Device(s) takes one of these numbers (1-{len(devices)}) as its target, or "
          f"Enter for all of them.")


def merge_for_write(existing, devices):
    """The rows to write: the data file's rows (existing, a DeviceDB), updated with the device
    database. Returns (rows, {'added', 'updated', 'unchanged'} counts). Matched by serial number, or
    for a file row with none yet, by IP or hostname. 'notes' and columns the tool doesn't know keep
    the file's values."""
    counts = {'added': 0, 'updated': 0, 'unchanged': 0}
    merged = DeviceDB()
    merged.devices = {serial: dict(row) for serial, row in existing.devices.items()}
    merged.unkeyed = [dict(row) for row in existing.unkeyed]
    touched = set()
    for row in devices.rows():
        serial = row.get('serial')
        target = merged.devices.get(serial) if serial else None
        if target is None:
            loose = merged.match(ip=row.get('ip'), hostname=row.get('hostname'))
            if loose is not None and (not loose.get('serial') or loose.get('serial') == serial):
                target = loose
                if serial and loose in merged.unkeyed:
                    merged.unkeyed.remove(loose)
                    merged.devices[serial] = loose
        if target is None:
            new = dict(row)
            if serial:
                merged.devices[serial] = new
            else:
                merged.unkeyed.append(new)
            counts['added'] += 1
            touched.add(id(new))
            continue
        if id(target) in touched:
            continue
        touched.add(id(target))
        before = dict(target)
        for key, value in row.items():
            if key == 'notes' and target.get('notes'):
                continue
            if value not in (None, ''):
                target[key] = value
        counts['updated' if target != before else 'unchanged'] += 1
    return merged.rows(), counts


def write_data_file(config):
    """Main Menu option 5: ask for the data file (the current one by default), then create it, or
    update it with the device database. Rows already in the file are kept; a backup of the old file
    is saved as <name>.bak first. The file becomes this run's data file."""
    import csv
    stage('Write Local Data File')
    path = ask_data_path(config, 'write')
    if path is None:
        return
    existing, header = DeviceDB(), []
    if path.exists():
        try:
            rows, header = read_data_rows(path)
        except (OSError, UnicodeDecodeError) as e:
            print(f"Could not read {path}: {getattr(e, 'strerror', None) or e} - nothing written.")
            return
        for row in rows:
            existing.add_row(row)
    rows, counts = merge_for_write(existing, DEVICES)
    extra = [c for c in header if c not in DATA_FIELDS]
    for row in rows:
        extra += [c for c in row if c not in DATA_FIELDS and c not in extra]
    if not path.exists():
        print(f"Creating {path} with {len(rows)} firewall(s)" + (' - an empty template with every column.'
                                                                  if not rows else '.'))
    else:
        print(f"Updating {path}: {counts['added']} added, {counts['updated']} updated, {counts['unchanged']} "
              f"unchanged, {len(existing) - counts['updated'] - counts['unchanged']} kept as they were.")
        if not counts['added'] and not counts['updated']:
            print("Nothing new to write.")
            DEVICES.source, DEVICES.changed = path, False
            return
        if not confirm(f"Update {path.name}? The current file is kept as {path.name}.bak"):
            print("Nothing written.")
            return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            shutil.copyfile(path, path.with_name(path.name + '.bak'))
        temp = path.with_name(path.name + '.tmp')
        with open(temp, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, DATA_FIELDS + extra, restval='', extrasaction='ignore')
            writer.writeheader()
            for row in sorted(rows, key=lambda r: (r.get('hostname') or r.get('ip') or '').lower()):
                writer.writerow(row)
        os.replace(temp, path)
    except OSError as e:
        print(f"Could not write {path}: {e.strerror}")
        return
    DEVICES.source, DEVICES.changed = path, False
    print(f"Saved {path}.")


# ---------------------------------------------------------------- settings

def config_text(value):
    """A config.yml value as Revert Settings lists it."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, list):
        return ', '.join(map(str, value))
    return '' if value is None else str(value)


def edit_setting(config, setting, path=None):
    """Open one setting: show it, then save what's typed straight to config.yml, or path (save_settings)."""
    stage(setting.key)
    print(textwrap.fill(setting.help, 100))
    limits = setting.limits()
    print(f"Default: [{setting.show(setting.default)}]" + (f"   Range: {limits}" if limits else '')
          + ('   Takes effect the next time the tool starts.' if setting.restart else ''))
    print(EDIT_HINT + (" A list is comma separated; - alone empties it." if setting.kind == 'list' else ''))
    current = config.get(setting.key)
    value = edit_value(setting.key, current, setting.default, setting.parse, setting.show)
    if value is CANCEL:
        print("Cancelled - nothing changed.")
        return
    if value == current and type(value) is type(current):
        print(f"No change - {setting.key} stays [{setting.show(current)}].")
        return
    if save_settings(config, {setting.key: value}, path):
        print(f"Saved: {setting.key} = [{setting.show(value)}]"
              + (' - takes effect the next time the tool starts.' if setting.restart else '.'))


def category_menu(config, name, categories=None, path=None):
    """One Settings category: its settings with their current values; picking one opens it."""
    settings = (categories or SETTING_CATEGORIES)[name]
    while True:
        choice = menu(name, [f"{s.key} [{s.show(config.get(s.key))}]" for s in settings])
        if choice == '0':
            return
        edit_setting(config, settings[int(choice) - 1], path)


def settings_menu(config):
    """Main Menu option 7: Application Settings (config.yml) or Health Check Thresholds
    (health_checks.yaml)."""
    while True:
        choice = menu('Settings', ['Application Settings', 'Health Check Thresholds'])
        if choice == '1':
            application_settings(config)
        elif choice == '2':
            health_thresholds()
        else:
            return


def application_settings(config):
    """Settings > Application Settings: every config.yml setting, by category, plus the JumpHosts. Each
    change is written to config.yml straight away; Revert Settings (9) goes back to the copy before the
    last one."""
    names = list(SETTING_CATEGORIES)
    print(f"\nChanges are saved to {CONFIG_PATH} as you make them. The copy before each change is kept as "
          f"{CONFIG_BACKUP.name} - Revert Settings goes back to it.")
    options = names + ['JumpHosts']
    options += [None] * (8 - len(options)) + ['Revert Settings']
    while True:
        choice = menu('Application Settings', options)
        if choice == '0':
            return
        number = int(choice)
        if number <= len(names):
            category_menu(config, names[number - 1])
        elif number == len(names) + 1:
            jump_hosts_menu(config)
        else:
            revert_settings(config)


def health_thresholds():
    """Settings > Health Check Thresholds: one category per health check - its on/off switch and its
    thresholds - written to health_checks.yaml as they change. Revert Thresholds goes back to the
    copy before the last change."""
    health = load_health_checks()
    names = list(HEALTH_CATEGORIES)
    print(f"\nChanges are saved to {HEALTH_PATH} as you make them. The copy before each change is kept as "
          f"{backup_of(HEALTH_PATH).name} - Revert Thresholds goes back to it.")
    while True:
        options = [f"{name} [{'On' if health[f'{key}_enabled'] else 'Off'}]"
                   for name, (key, _) in zip(names, HEALTH_CHECKS)] + ['Revert Thresholds']
        choice = menu('Health Check Thresholds', options)
        if choice == '0':
            return
        number = int(choice)
        if number <= len(names):
            category_menu(health, names[number - 1], HEALTH_CATEGORIES, HEALTH_PATH)
        else:
            revert_settings(health, HEALTH_PATH)


def revert_settings(config, path=None):
    """Application Settings option 9 (or Revert Thresholds, for health_checks.yaml): swap config.yml
    with config.yml.bak (the copy before the last change), after listing what that changes. The
    replaced file becomes the backup, so a revert can be undone the same way. The reverted settings
    are used straight away."""
    path = path or CONFIG_PATH
    backup = backup_of(path)
    app = path == CONFIG_PATH
    stage('Revert Settings' if app else 'Revert Thresholds')
    if not backup.exists():
        print(f"There's no previous copy yet - {backup.name} is saved the first time a setting changes.")
        return
    try:
        current_text = path.read_bytes().decode('utf-8')
        backup_text = backup.read_bytes().decode('utf-8')
        current = yaml.safe_load(current_text) or {}
        backup_values = yaml.safe_load(backup_text) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        print(f"Can't read the config files: {getattr(e, 'strerror', None) or e} - nothing changed.")
        return
    changed = sorted(k for k in set(current) | set(backup_values) if current.get(k) != backup_values.get(k))
    if not changed:
        print(f"{backup.name} is the same as {path.name} - nothing to revert.")
        return
    saved = datetime.datetime.fromtimestamp(backup.stat().st_mtime)
    print(f"{backup.name} was saved {saved:%Y-%m-%d %H:%M:%S}. Reverting changes:")
    for key in changed:
        if key == 'jump_hosts':
            before, after = read_jump_hosts(current.get(key), quiet=True), read_jump_hosts(backup_values.get(key), quiet=True)
            print(f"  jump_hosts: {len(before)} JumpHost(s) -> {len(after)}, "
                  f"#{', #'.join(str(n) for n in sorted(set(before) | set(after)) if before.get(n) != after.get(n))} differ")
        else:
            print(f"  {key}: [{config_text(current.get(key))}] -> [{config_text(backup_values.get(key))}]")
    if not confirm(f"Revert? The current {path.name} becomes {backup.name}, so this can be undone the same way"):
        print("Nothing changed.")
        return
    try:
        temp = path.with_name(path.name + '.tmp')
        temp_backup = backup.with_name(backup.name + '.tmp')
        temp.write_text(backup_text, encoding='utf-8', newline='')
        temp_backup.write_text(current_text, encoding='utf-8', newline='')
        os.replace(temp, path)
        os.replace(temp_backup, backup)
    except OSError as e:
        print(f"Couldn't revert: {e.strerror} - check {path.name} and {backup.name}.")
        return
    reloaded = load_config() if app else load_health_checks()
    config.clear()
    config.update(reloaded)
    if not app:
        print("Reverted - the thresholds above apply from the next health check.")
        return
    if config['verify_ssl'] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("Reverted - the settings above are in use now"
          + ('; log_folder and log_retention_days take effect the next time the tool starts.'
             if {'log_folder', 'log_retention_days'} & set(changed) else '.'))


# ---------------------------------------------------------------- JumpHosts

# A JumpHost in config.yml (jump_hosts, keyed by its fixed number): (key, ssh keyword, help, default)
JUMP_FIELDS = [
    ('host', 'Host', "A name for this JumpHost - letters, digits, '.', '_' or '-'. ProxyJump refers to it.", ''),
    ('hostname', 'HostName', "The JumpHost's address: an IP or DNS name.", ''),
    ('user', 'User', "Your username on the JumpHost.", ''),
    ('port', 'Port', "Its SSH port (1-65535).", 22),
    ('identity_file', 'IdentityFile', "Your private key for it, e.g. ~/.ssh/id_ed25519_bastion. Blank: ssh's usual "
                                      "keys, or a password you type.", ''),
    ('identities_only', 'IdentitiesOnly', "yes: offer ssh only the IdentityFile key (used only with an IdentityFile).",
     True),
    ('proxy_jump', 'ProxyJump', "Another JumpHost (its Host or number) this one is reached through; blank connects to it "
                                "directly. Used only while Chained JumpHosts is On", ''),
]
JUMP_REQUIRED = ('host', 'hostname', 'user')
JUMP_ALIAS = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
JUMP_USER = re.compile(r'^[^\s@:"]+$')


def read_jump_hosts(raw, quiet=False):
    """jump_hosts from config.yml as {number: JumpHost dict with every JUMP_FIELDS key}. Entries that
    can't be used are left out, with a warning."""
    def warn(text):
        if not quiet:
            print(f"WARNING: jump_hosts in config.yml: {text} - left out.")
    hosts = {}
    if not raw:
        return hosts
    if not isinstance(raw, dict):
        warn("isn't a list of numbered JumpHosts")
        return hosts
    for number, entry in raw.items():
        if not (isinstance(number, int) or str(number).isdigit()) or int(number) < 1 or not isinstance(entry, dict):
            warn(f"entry {number!r} isn't a numbered JumpHost")
            continue
        jh = {}
        for key, _, _, default in JUMP_FIELDS:
            value = entry.get(key, default)
            if key == 'port':
                value = int(value) if str(value).isdigit() and 1 <= int(value) <= 65535 else 22
            elif key == 'identities_only':
                value = value if isinstance(value, bool) else str(value).lower() in ON_WORDS
            else:
                value = '' if value is None else str(value).strip()
            jh[key] = value
        if not all(jh[key] for key in JUMP_REQUIRED):
            warn(f"#{number} needs a host, hostname and user")
            continue
        hosts[int(number)] = jh
    return dict(sorted(hosts.items()))


def jump_number(hosts, alias):
    """The number of the JumpHost named alias, or None."""
    return next((n for n, jh in hosts.items() if jh['host'].lower() == alias.lower()), None)


def jump_route(hosts, number, chaining=True):
    """JumpHost numbers from the first one connected to through to number, following ProxyJump while
    chaining is on. Raises ValueError for a ProxyJump that names no JumpHost or loops."""
    route = []
    current = number
    while True:
        if current in route:
            raise ValueError(f"ProxyJump loops back to #{current} {hosts[current]['host']}")
        route.append(current)
        alias = hosts[current]['proxy_jump'] if chaining else ''
        if not alias:
            return list(reversed(route))
        following = jump_number(hosts, alias)
        if following is None:
            raise ValueError(f"#{current} {hosts[current]['host']}'s ProxyJump '{alias}' isn't a JumpHost")
        current = following


def route_text(hosts, route, target=None):
    return ' -> '.join(['you'] + [f"#{n} {hosts[n]['host']}" for n in route] + ([target] if target else []))


def ssh_quote(value):
    return f'"{value}"' if re.search(r'\s', value) else value


def jump_block(number, jh, chaining, extra=()):
    """One JumpHost as ssh_config lines (the form View a JumpHost Config shows)."""
    lines = [f"# {number}. {jh['host']}", f"Host {jh['host']}", f"    HostName {jh['hostname']}",
             f"    User {jh['user']}", f"    Port {jh['port']}"]
    if jh['identity_file']:
        lines += [f"    IdentityFile {ssh_quote(jh['identity_file'])}",
                  f"    IdentitiesOnly {'yes' if jh['identities_only'] else 'no'}"]
    lines += [f"    {line}" for line in extra]
    if jh['proxy_jump'] and chaining:
        lines.append(f"    ProxyJump {jh['proxy_jump']}")
    return lines


def ssh_config_text(config, batch=False):
    """Every JumpHost as an ssh config file, for ssh -F. Each one waits request_timeout to connect; a
    JumpHost with no ProxyJump (or every one, with Chained JumpHosts off) says ProxyJump none so
    nothing else can route it. batch turns every prompt off (Test JumpHost Connectivity). Your own
    ~/.ssh/config is included after them, as ssh would read it without -F."""
    chaining = config[JUMP_CHAINING.key]
    lines = [f"# Written by {APP_TITLE} from jump_hosts in config.yml for one ssh run, then deleted.", '']
    for number, jh in config['jump_hosts'].items():
        extra = [f"ConnectTimeout {config['request_timeout']}"] + (['BatchMode yes'] if batch else [])
        block = jump_block(number, jh, chaining, extra)
        if not (jh['proxy_jump'] and chaining):
            block.append('    ProxyJump none')
        lines += block + ['']
    lines += ['# Your own ssh settings, after the ones above', 'Match all', '    Include ~/.ssh/config', '']
    return '\n'.join(lines)


def short_path(path):
    """path in its 8.3 short form where Windows has one (no spaces), else as it is."""
    import ctypes
    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    return Path(buffer.value) if 0 < length < len(buffer) else Path(path)


@contextlib.contextmanager
def ssh_config_file(config, batch=False):
    """The JumpHosts written to a temporary ssh config file for one ssh run; yields its path and
    deletes it afterwards. It holds no passwords. ssh hands the path on to each JumpHost connection
    without quotes, so it has to have no spaces (ValueError otherwise)."""
    import tempfile
    folder = Path(tempfile.mkdtemp(prefix='net-dev-cli-ssh-'))
    try:
        path = folder / 'ssh_config'
        path.write_text(ssh_config_text(config, batch), encoding='utf-8')
        path = short_path(path)
        if re.search(r'\s', str(path)):
            raise ValueError(f"ssh can't use a JumpHost config file in a folder with a space in its path ({path}) - "
                             f"set TEMP to a folder without spaces")
        yield str(path)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def jump_rows(config):
    chaining = config[JUMP_CHAINING.key]
    return [{
        '#': str(number), 'Host': jh['host'], 'HostName': jh['hostname'], 'User': jh['user'],
        'Port': str(jh['port']), 'IdentityFile': jh['identity_file'] or '-',
        'ProxyJump': (jh['proxy_jump'] + ('' if chaining else ' (Chained off)')) if jh['proxy_jump'] else '-',
    } for number, jh in config['jump_hosts'].items()]


def pick_jump_host(config, label):
    """List the JumpHosts and pick one by its number; None if there are none or none is picked."""
    if not config['jump_hosts']:
        print("No JumpHosts yet - add one under Settings > Application Settings > JumpHosts > Add/Update a JumpHost.")
        return None
    print()
    print_table(jump_rows(config))
    chosen = pick(label, {n: n for n in config['jump_hosts']}, single=True)
    return chosen[0] if chosen else None


def jump_key_path(value):
    return Path(os.path.expandvars(os.path.expanduser(value)))


def jump_parser(key, others):
    """The check for one JumpHost field as typed: returns the value to store, or raises ValueError.
    others are the other JumpHosts, {number: JumpHost}."""
    def host(text):
        if not JUMP_ALIAS.match(text):
            raise ValueError("Use letters, digits, '.', '_' or '-' (starting with a letter or digit).")
        if jump_number(others, text) is not None:
            raise ValueError(f"JumpHost #{jump_number(others, text)} is already called {text}.")
        return text

    def hostname(text):
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            pass
        if IPV4_PATTERN.match(text) or not HOSTNAME_PATTERN.match(text):
            raise ValueError(f"'{text}' isn't a valid IP address or hostname.")
        return text

    def user(text):
        if not JUMP_USER.match(text):
            raise ValueError("A username can't contain spaces, '@', ':' or quotes.")
        return text

    def port(text):
        if not text.isdigit() or not 1 <= int(text) <= 65535:
            raise ValueError("Enter a port from 1 to 65535.")
        return int(text)

    def onoff(text):
        if text.lower() not in ON_WORDS | OFF_WORDS:
            raise ValueError("Enter yes or no.")
        return text.lower() in ON_WORDS

    def proxy(text):
        number = int(text) if text.isdigit() else jump_number(others, text)
        if number not in others:
            raise ValueError(f"'{text}' isn't another JumpHost - enter its Host or number.")
        return others[number]['host']

    return {'host': host, 'hostname': hostname, 'user': user, 'port': port,
            'identities_only': onoff, 'proxy_jump': proxy}.get(key, lambda text: text.strip('"'))


def jump_show(key):
    if key == 'identities_only':
        return lambda value: 'yes' if value else 'no'
    return lambda value: str(value)


def list_jump_hosts(config):
    stage('List JumpHosts')
    if not config['jump_hosts']:
        print("No JumpHosts yet - add one with Add/Update a JumpHost.")
        return
    print_table(jump_rows(config))
    print(f"\nChained JumpHosts is {JUMP_CHAINING.show(config[JUMP_CHAINING.key])}.")


def view_jump_host(config):
    stage('View a JumpHost Config')
    number = pick_jump_host(config, 'View JumpHost')
    if number is None:
        return
    hosts, chaining = config['jump_hosts'], config[JUMP_CHAINING.key]
    jh = hosts[number]
    print()
    print('\n'.join(jump_block(number, jh, chaining=True)))
    if jh['proxy_jump'] and not chaining:
        print("    (ProxyJump is ignored while Chained JumpHosts is Off)")
    try:
        print(f"\nRoute: {route_text(hosts, jump_route(hosts, number, chaining))} -> firewall")
    except ValueError as e:
        print(f"\nThis JumpHost can't be used: {e}.")


def edit_jump_host(config):
    """Add/Update a JumpHost: Enter takes the next free number (CREATING); a number that exists is
    shown for UPDATING, one that doesn't starts blank (CREATING). Every field is asked in turn, with
    its current value in [ ]; Esc at any field cancels the lot. Saved to config.yml at the end."""
    stage('Add/Update a JumpHost')
    hosts = config['jump_hosts']
    if hosts:
        print_table(jump_rows(config))
    following = max(hosts, default=0) + 1
    text = prompt('JumpHost number', str(following)).strip()
    if not INDEX_PATTERN.match(text) or int(text) < 1:
        print("Enter a JumpHost number (1 or more). Nothing changed.")
        return
    number = int(text)
    old = hosts.get(number)
    print(f"\n{'UPDATING' if old else 'CREATING'} JumpHost #{number}")
    print(EDIT_HINT)
    entry = dict(old) if old else {key: default for key, _, _, default in JUMP_FIELDS}
    others = {n: jh for n, jh in hosts.items() if n != number}
    chaining = config[JUMP_CHAINING.key]
    for key, keyword, help, default in JUMP_FIELDS:
        print(f"\n  {help}" + (f" (now {JUMP_CHAINING.show(chaining)})." if key == 'proxy_jump' else ''))
        while True:
            value = edit_value(keyword, entry[key], default, jump_parser(key, others), jump_show(key),
                               required=key in JUMP_REQUIRED)
            if value is CANCEL:
                print("Cancelled - nothing saved.")
                return
            if key == 'identity_file' and value and not jump_key_path(value).is_file():
                print(f"  There's no file at {jump_key_path(value)}.")
                if not confirm("  Keep it anyway?"):
                    continue
            if key == 'proxy_jump' and value:
                # As it will be saved: a rename of this JumpHost carried into the others' ProxyJump
                trial = {n: ({**jh, 'proxy_jump': entry['host']}
                             if old and jh['proxy_jump'].lower() == old['host'].lower() else jh)
                         for n, jh in others.items()}
                try:
                    jump_route({**trial, number: {**entry, key: value}}, number)
                except ValueError as e:
                    print(f"  {e}.")
                    continue
            break
        entry[key] = value
    if entry == old:
        print("\nNo changes - nothing saved.")
        return
    updated = {n: dict(jh) for n, jh in hosts.items()}
    if old and old['host'] != entry['host']:
        for n, jh in updated.items():
            if n != number and jh['proxy_jump'].lower() == old['host'].lower():
                jh['proxy_jump'] = entry['host']
                print(f"#{n} {jh['host']}'s ProxyJump now says {entry['host']}.")
    updated[number] = entry
    updated = dict(sorted(updated.items()))
    print()
    print('\n'.join(jump_block(number, entry, chaining=True)))
    if save_settings(config, {'jump_hosts': updated}):
        print(f"\nSaved JumpHost #{number} {entry['host']}.")


def delete_jump_host(config):
    stage('Delete a JumpHost')
    hosts = config['jump_hosts']
    number = pick_jump_host(config, 'Delete JumpHost')
    if number is None:
        return
    alias = hosts[number]['host']
    users = [f"#{n} {jh['host']}" for n, jh in hosts.items()
             if n != number and jh['proxy_jump'].lower() == alias.lower()]
    if users:
        print(f"#{number} {alias} can't be deleted: {', '.join(users)} reach(es) it through ProxyJump. "
              f"Change that first.")
        return
    print()
    print('\n'.join(jump_block(number, hosts[number], chaining=True)))
    if not confirm(f"Delete JumpHost #{number} {alias}?"):
        print("Nothing deleted.")
        return
    if save_settings(config, {'jump_hosts': {n: jh for n, jh in hosts.items() if n != number}}):
        print(f"Deleted JumpHost #{number} {alias}.")


def ssh_env():
    """This tool's environment without any SSH_ASKPASS settings, for ssh."""
    return {name: value for name, value in os.environ.items()
            if name.upper() not in ('SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', ASKPASS_ENV)}


def ssh_test_verdict(code, stderr):
    """(what a JumpHost test's ssh result means, whether the JumpHost wants a password the test
    couldn't type)."""
    if code == 0:
        return "OK - logged in with ssh and ran exit.", False
    low = stderr.lower()
    if 'remote host identification has changed' in low:
        return ("FAIL - a host key on the route has CHANGED since you last connected. Check with whoever runs "
                "the JumpHost before connecting."), False
    if 'host key verification failed' in low:
        return ("FAIL - a host key on the route isn't in your known_hosts yet. Connect to it once with ssh and "
                "check the fingerprint before accepting it."), False
    if 'could not resolve hostname' in low:
        return "FAIL - a hostname on the route can't be resolved.", False
    if 'timed out' in low:
        return "FAIL - timed out connecting (request_timeout).", False
    if 'connection refused' in low:
        return "FAIL - the connection was refused.", False
    denied = re.search(r'permission denied \(([^)]*)\)', low)
    if denied:
        methods = [m.strip() for m in denied[1].split(',')]
        typed = any(m in methods for m in ('password', 'keyboard-interactive'))
        if 'publickey' not in methods:
            return f"FAIL - it doesn't take keys (it allows {denied[1]}), and the test can't type a password.", typed
        unreadable = ' The IdentityFile can\'t be read.' if 'no such' in low else ''
        return (f"FAIL - the key wasn't accepted (it allows {denied[1]}).{unreadable}"
                + (" It also takes a password, which the test can't type." if typed else '')), typed
    if 'connection closed' in low or 'kex_exchange_identification' in low or 'connection reset' in low:
        return "FAIL - the connection was closed while it was being set up.", False
    return f"FAIL - ssh exit code {code}.", False


def test_jump_host(config):
    """Test JumpHost Connectivity: reach the first JumpHost on the route, then log in to the chosen one
    with ssh, end to end through any ProxyJump, with no prompts (a key login), and run exit. Uses
    request_timeout to connect and check_timeout for the whole test."""
    stage('Test JumpHost Connectivity')
    number = pick_jump_host(config, 'Test JumpHost')
    if number is None:
        return
    hosts = config['jump_hosts']
    alias = hosts[number]['host']
    try:
        route = jump_route(hosts, number, config[JUMP_CHAINING.key])
    except ValueError as e:
        print(f"This JumpHost can't be used: {e}.")
        return
    first = hosts[route[0]]
    print(f"\nRoute: {route_text(hosts, route)}")
    try:
        socket.create_connection((first['hostname'], first['port']), timeout=config['request_timeout']).close()
        print(f"  Reached {first['hostname']} port {first['port']}.")
    except socket.gaierror:
        print(f"  FAIL - can't resolve {first['hostname']}.")
        return
    except OSError as e:
        print(f"  FAIL - can't reach {first['hostname']} port {first['port']}: {e.strerror or e}.")
        return
    if not SSH_CLIENT.exists():
        print(f"  Can't test the login: Windows' OpenSSH client isn't installed ({SSH_CLIENT}).")
        return
    print(f"  Logging in to #{number} {alias} with ssh (key login only, no prompts)...")
    try:
        with ssh_config_file(config, batch=True) as path:
            result = subprocess.run([str(SSH_CLIENT), '-F', path, alias, 'exit'], capture_output=True, text=True,
                                    timeout=config['check_timeout'], env=ssh_env(), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print(f"  FAIL - no answer within check_timeout ({config['check_timeout']}s).")
        return
    except (OSError, ValueError) as e:
        print(f"  FAIL - {e}")
        return
    verdict, typed = ssh_test_verdict(result.returncode, result.stderr)
    print(f"  {verdict}")
    if result.returncode:
        for line in [ln for ln in result.stderr.splitlines() if ln.strip()][-3:]:
            print(f"    ssh: {line.strip()}")
    if typed and confirm("Test again, typing the password (and anything else ssh asks) yourself?"):
        print()
        try:
            with ssh_config_file(config) as path:
                code = subprocess.run([str(SSH_CLIENT), '-F', path, alias, 'exit'], env=ssh_env()).returncode
        except (OSError, ValueError) as e:
            print(f"  FAIL - {e}")
            return
        print(f"  {'OK - logged in and ran exit.' if code == 0 else f'FAIL - ssh exit code {code}; its message is above.'}")


def jump_hosts_menu(config):
    """Settings option 5: the JumpHosts Connect via SSH can go through, kept in config.yml."""
    while True:
        choice = menu('JumpHosts', [
            'List JumpHosts', 'View a JumpHost Config', 'Test JumpHost Connectivity', 'Add/Update a JumpHost',
            'Delete a JumpHost', f"Chained JumpHosts [{JUMP_CHAINING.show(config[JUMP_CHAINING.key])}]",
        ])
        if choice == '0':
            return
        {'1': list_jump_hosts, '2': view_jump_host, '3': test_jump_host, '4': edit_jump_host,
         '5': delete_jump_host, '6': lambda c: edit_setting(c, JUMP_CHAINING)}[choice](config)


def git(*args):
    """Run git in this tool's folder. Never prompts in the terminal: if the repo needs credentials,
    they come from the Git Credential Manager like any other git command."""
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
    return subprocess.run(['git', '-C', str(BASE_DIR), *args], capture_output=True, text=True,
                          timeout=GIT_TIMEOUT, env=env)


def check_tool_updates():
    """Main Menu option 8: fetch from the repo it was cloned from, list any new commits, and offer to pull them."""
    stage('Check for updates')
    if FROZEN:
        print(f"This is the standalone EXE, which can't update itself.\n"
              f"Get the latest version from {REPO_URL}, or build a new EXE from it with build_exe.ps1.")
        return
    if not (BASE_DIR / '.git').exists():
        print(f"This copy wasn't installed with git clone, so it can't update itself.\n"
              f"Get the latest version from {REPO_URL}")
        return
    try:
        # The repo this clone actually fetches from, shown without any credentials in its URL
        remote = re.sub(r'//[^/@]*@', '//', git('ls-remote', '--get-url').stdout.strip())
        print(f"Checking {remote or 'the remote repo'}...")
        fetch = git('fetch', '--quiet')
        if fetch.returncode:
            print(f"Could not reach the repo: {fetch.stderr.strip()}")
            return
        upstream = git('rev-parse', '--abbrev-ref', '@{upstream}')
        if upstream.returncode:
            print("This branch doesn't track a remote branch, so there's nothing to compare against.")
            return
        upstream = upstream.stdout.strip()
        new = git('log', '--format=%h  %ad  %s', '--date=short', f"HEAD..{upstream}").stdout.splitlines()
        if not new:
            print(f"Up to date with {upstream}.")
            return

        print(f"\n{len(new)} update(s) available on {upstream}:")
        for line in new:
            print(f"  {line}")
        changed = git('diff', '--name-only', 'HEAD', upstream).stdout.split()
        print()
        if not confirm("Download and apply them now?"):
            return
        # Fast-forward only: never merges over local edits or local commits
        pull = git('pull', '--ff-only', '--quiet')
        if pull.returncode:
            print(f"Update failed: {pull.stderr.strip()}")
            print("This usually means files in this folder were changed locally. "
                  "Nothing was overwritten.")
            return
    except FileNotFoundError:
        print("git isn't installed, or isn't on PATH.")
        return
    except subprocess.TimeoutExpired:
        print(f"git didn't finish within {GIT_TIMEOUT}s.")
        return

    print("Updated.")
    if any(name in changed for name in DEPENDENCY_FILES):
        print("The dependencies changed - run 'poetry install' before starting the tool again.")
    print("Exit and start the tool again to use the new version.")


# ---------------------------------------------------------------- main

def main():
    global LOG
    config = load_config()
    LOG = start_log(config)
    try:
        if config['verify_ssl'] is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            print(f"verify_ssl is false - certificates aren't checked against a CA. Each firewall's is trusted the "
                  f"first time it connects, and has to match every time after ({CERTS_PATH.name}).")
        watch_console_close()
        while True:
            try:
                # Manage Devices and Disconnect only while firewalls are connected
                connected = bool(CONNECTION.firewalls)
                choice = menu(f"{APP_TITLE} - Main Menu", [
                    'Connect to Device(s)',
                    f"Manage Devices ({CONNECTION.connected} connected)" if connected else None,
                    'Disconnect' if connected else None,
                    'Load Local Data File',
                    'Write Local Data File',
                    'View Devices' if len(DEVICES) else None,
                    'Settings',
                    'Check for Tool Updates',
                ], zero='Exit')
                if choice == '1':
                    connect(config)
                elif choice == '2':
                    manage_devices(config)
                elif choice == '3':
                    disconnect('Disconnect')
                elif choice == '4':
                    # Just a one-line summary; View Devices shows them
                    load_data_menu(config)
                elif choice == '5':
                    write_data_file(config)
                elif choice == '6':
                    view_devices()
                elif choice == '7':
                    settings_menu(config)
                elif choice == '8':
                    check_tool_updates()
                else:
                    break
            except IdleDisconnect:
                # The idle timeout disconnected while at the Main Menu or in one of its options
                print("Disconnected by the application idle timeout - back to the Main Menu.")
                ACTIVITY.disconnected.clear()
    except KeyboardInterrupt:
        print()
    except Exception:
        if not FROZEN:
            # Python prints the traceback once the log is closed, so record it here
            log_only(traceback.format_exc())
            disconnect('the tool stopped with an error')
            raise
        # Started by double-click, the console window would close before the error could be read
        traceback.print_exc()
        disconnect('the tool stopped with an error')
        ask("\nThe tool stopped with an error. Press Enter to close this window.")
    finally:
        # Exit, Ctrl+C or an error: log out of anything still connected before the tool ends
        try:
            disconnect('exit')
        except BaseException:
            log_only(f"Disconnect at exit stopped: {traceback.format_exc()}")
        if LOG:
            LOG.close()
            LOG = None


if __name__ == '__main__':
    if ASKPASS_ENV in os.environ:
        # Started by ssh to answer a prompt during Connect via SSH - not a new run of the tool
        sys.exit(askpass_main(sys.argv[1:]))
    main()
