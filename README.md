# Net_Dev_CLI

Checks the PAN-OS version and dynamic content (Apps & Threats, Antivirus, WildFire and more) installed on Palo Alto firewalls over the XML API, and what updates are available.

## Prerequisites

- **Python 3.13** or higher
- **Poetry** for dependency management
- HTTPS (443) access to each firewall's management interface
- An admin account on each firewall whose role allows **XML API > Operational Requests**
- For Connect via SSH only: Windows' built-in **OpenSSH Client** (installed by default on Windows 10 1809 and later; otherwise add it under Settings > System > Optional features) and SSH (22) access to the management interface

## Installation

```powershell
git clone https://github.com/wmfreeman/palo-toolkit.git
cd palo-toolkit
poetry lock
poetry install
```

Install with `git clone` as shown, so the tool can [update itself](#main-menu).

### Standalone EXE

For a machine without Python or Poetry, build a single `Net_Dev_CLI.exe` that has Python and every dependency inside it:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
```

The script runs `poetry install`, which includes PyInstaller as a dev dependency, then writes `dist\Net_Dev_CLI.exe` (about 12 MB). Build it on Windows, from a clone with the dev dependencies.

- **Running it:** copy the EXE anywhere and double-click it, or run it from a terminal. It's a console program, so it opens its own window when double-clicked.
- **Config:** on first run it creates `config\config.yml` next to the EXE, from the skeleton bundled inside it, and `config\health_checks.yaml` the first time the health check thresholds are needed. Keep the EXE in a folder you can write to.
- **Errors:** if the EXE stops with an unexpected error, it prints the error and waits for Enter, so the window doesn't close before you can read it.
- **Updates:** the EXE can't update itself, so Check for Tool Updates says so. Build a new EXE from an updated clone instead.
- **Start-up:** each run unpacks itself to a temporary folder first, so it takes a few seconds to start.
- **Security tools:** they sometimes flag PyInstaller EXEs they haven't seen before. If yours blocks it, it may need allow-listing.

`config/config.yml` is created from `config/skeleton_config.yml` on first run, and `config/health_checks.yaml` (the [health check thresholds](#health-check-thresholds)) from `config/skeleton_health_checks.yaml` the first time it's needed. Change them from [Settings](#settings) (Main Menu option 7), or by editing them. Set `default_target` to the firewalls you usually check (any form the Target prompt accepts), or leave it blank. Once the [local data file](#local-data-file) holds devices, those are the default instead.

Certificate checking is off by default (`verify_ssl: false`) because firewall management interfaces use self-signed certificates. Set it to `true`, or to the path of a CA bundle, if yours are signed by a CA you trust.

## Usage

```powershell
poetry run python palo_image_updater.py
```

In every menu, `0` goes back one level. In the Main Menu, `0` exits, and first [disconnects](#disconnect) any firewalls still connected.

### Main Menu

The Main Menu is the application level: connecting, the local data file, settings and tool updates. The firewalls you connect to have their own menu, [Palo Firewall Management](#palo-firewall-management) (Manage Devices).

```text
=== Net_Dev_CLI - Main Menu ===
1 - Connect to Device(s)
2 - Manage Devices (3 connected)
3 - Disconnect
4 - Load Local Data File
5 - Write Local Data File
6 - View Devices
7 - Settings
8 - Check for Tool Updates
0 - Exit
```

| Option | What it does |
|--------|--------------|
| 1 - Connect to Device(s) | Targets (the known devices by default) and authentication, then back to the Main Menu. Loads the data file first only if the device database is empty. Firewalls you connect to are added to the device database. While firewalls are connected, the new ones join them (see below). |
| 2 - Manage Devices | [Palo Firewall Management](#palo-firewall-management) for the connected firewalls. Only shown while connected; the count is the firewalls holding an API key. |
| 3 - Disconnect | Logs out of every connected firewall and clears the keys and the password (see [Disconnect](#disconnect)). Only shown while connected. |
| 4 - Load Local Data File | Asks which [data file](#local-data-file) to load (Enter takes the current one), then loads it **in place of** the device database and says how many firewalls it read, in one line |
| 5 - Write Local Data File | Asks which data file to write (Enter takes the current one), then creates it or updates it with the device database (see [Local data file](#local-data-file)) |
| 6 - View Devices | Lists the known devices, numbered. Only shown once the device database holds some: after loading a data file, or after connecting. |
| 7 - Settings | Application Settings (every `config.yml` setting, by category, plus the JumpHosts for Connect via SSH) and Health Check Thresholds (`health_checks.yaml`). Each change is saved straight away (see [Settings](#settings)). |
| 8 - Check for Tool Updates | Checks the repo it was cloned from ([GitHub](https://github.com/wmfreeman/palo-toolkit)) for a newer version of this tool (see below) |
| 0 - Exit | [Disconnects](#disconnect) any firewalls still connected, with the same report as option 3, then exits |

**Staying connected.** After connecting, and after `0` in Palo Firewall Management, you're back here, still connected: the API keys, the password and the keep-alive carry on, and the [application idle timeout](#session-timeouts-and-the-keep-alive) still applies. Manage Devices opens Palo Firewall Management for them. Connect to Device(s) while connected adds firewalls to the session: they're numbered on from the ones already connected, only the new ones are authenticated (with their MFA pushes), and a firewall already connected isn't added twice (one that has lost its key is authenticated again). The authentication table is then shown for the whole session.

**The current data file** is the one last loaded or written this run, or `data_file` from the config until then. Load and Write offer it as the default, so you can load the data file, connect to a new list of firewalls (they're added to the device database), then write the data file to add them. If connections have added devices that haven't been written yet, Load asks before replacing them.

**View Devices** shows each device's number, serial number, hostname, IP, model, PAN-OS version, HA state, HA peer and when it was last seen. The numbers are the ones the Target prompt takes:

```text
=== View Devices ===
#  Serial           Hostname         IP        Model    PAN-OS  HA       HA Peer    Last seen
-  ---------------  ---------------  --------  -------  ------  -------  ---------  -------------------
1  (not connected)  fw5.example.lan  -         -        -       -        -          -
2  013201001234     site1-fw1        10.1.0.2  PA-3220  11.1.6  Active   site1-fw2  2026-11-15 09:12:40
3  013201005678     site1-fw2        10.1.0.3  PA-3220  11.1.6  Passive  site1-fw1  2026-11-15 09:12:41
```

They're in hostname order (or IP, for a device with no hostname yet), so a device can move once a connection learns its hostname. View Devices again before picking by number.

**Check for Tool Updates** runs `git fetch` and lists any new commits on the branch you're on, with their dates. It then asks before applying them with `git pull --ff-only`. That only fast-forwards, so it never overwrites local edits or merges over local commits; if there are any, it says so and changes nothing. After an update, exit and start the tool again. If `pyproject.toml` or `poetry.lock` changed, run `poetry install` first.

It uses your normal git credentials (Git Credential Manager on Windows) and never prompts in the terminal. It needs `git` on PATH, and a copy installed with `git clone`.

### Disconnect

Main Menu option 3, shown while firewalls are connected. Logs out of every connected firewall and clears the API keys and the password from memory.

- **The logout:** the keep-alive is stopped first, so no poll can log you back in. Then each firewall that holds a key gets `<delete><admin-sessions><username>{your username}</username></admin-sessions></delete>`, all at once. PAN-OS has no logout for a single API session, so the command targets every session that admin has on the firewall. In testing, a web UI session for the same admin stayed logged in.
- **The report:** one row per firewall. `Logged out` means the firewall confirmed it, or ended the session the request arrived on. `FAIL` gives the reason (no reply, refused, no permission for the command), and that session then ends at the firewall's own admin idle timeout. A firewall whose session had already ended is listed with `-`. One that never authenticated isn't listed.
- **The key is cleared either way**, whatever the firewall answers.

The same Disconnect runs, with the same report, when you:

- choose `0 - Exit` in the Main Menu
- press Ctrl+C
- hit an unexpected error
- reach the application idle timeout
- close the console window

**Closing the window** is the one exception to the on-screen report: Windows ends the process about 5 seconds after the window closes. So each logout gets 3 seconds, a firewall that's busy with another request is given 1 second before its key is just dropped, and the report goes to the run log only. Ending the process from Task Manager, or a power loss, gives no chance to log out. Those sessions end at the firewall's idle timeout.

### Settings

```text
=== Settings ===
1 - Application Settings
2 - Health Check Thresholds
0 - Back
```

**Application Settings** edits `config.yml`:

```text
=== Application Settings ===
1 - Targets & Data
2 - Connection
3 - Jobs & Downloads
4 - Files & Logs
5 - JumpHosts
9 - Revert Settings
0 - Back
```

Each category lists its settings with their current value in `[ ]`, e.g. `2 - keygen_timeout [90]`. Picking one shows what it does, its default and its range:

```text
=== keygen_timeout ===
Seconds to wait for keygen to answer - the time you have to approve the MFA push.
Default: [90]   Range: 10 or more (0 = the default)
Type a new value and press Enter to save it. Enter alone keeps the [value], Esc cancels, Del reverts to the default.
keygen_timeout [90]: 120
Saved: keygen_timeout = [120].
```

| Key | Does |
|-----|------|
| Type a value, Enter | Checks it (a number in range, an existing CA file, On/Off...) and saves it. A bad value says why and asks again. |
| Enter alone | Keeps the `[value]` |
| Esc | Cancels; nothing changes |
| Del | Sets the default and saves it |

- **Saved straight away.** Each change is written to `config.yml` as you make it and used for the rest of the run, so there's no Save option and no question on the way out. `log_folder` and `log_retention_days` take effect the next time the tool starts.
- **Your comments stay.** Only the changed setting's lines are rewritten. The result is read back and checked before it replaces the file.
- **Revert Settings (9).** Before each change, the file as it was is kept as `config.yml.bak`. Revert Settings lists what going back to it changes, asks, then swaps the two files, so a revert can be undone the same way.

**Health Check Thresholds** edits `health_checks.yaml` the same way: one category per check, showing whether it's on, then Revert Thresholds (17), which swaps the file with `health_checks.yaml.bak`. See [Health check thresholds](#health-check-thresholds).

```text
=== Health Check Thresholds ===
1 - System Info [On]
2 - Chassis LEDs [On]
...
8 - Interfaces [Off]
...
16 - Certificates [On]
17 - Revert Thresholds
0 - Back
```

```text
=== Interfaces ===
1 - interfaces_enabled [Off]
2 - interfaces_down [WARN]
3 - interfaces_ignore [ethernet1/8]
0 - Back
```

A severity setting takes `WARN`, `FAIL` or `OFF`. A list is typed comma separated, and `-` alone empties it.

#### JumpHosts

```text
=== JumpHosts ===
1 - List JumpHosts
2 - View a JumpHost Config
3 - Test JumpHost Connectivity
4 - Add/Update a JumpHost
5 - Delete a JumpHost
6 - Chained JumpHosts [On]
0 - Back
```

JumpHosts (bastions) that [Connect via SSH](#8---connect-via-ssh) can go through. They're kept in `config.yml` under `jump_hosts`, each with a **fixed number**: deleting #2 leaves a gap, and #3 stays #3.

- **Add/Update a JumpHost.** It asks for a number. Enter takes the next one (`CREATING JumpHost #4`). A number that exists shows its values (`UPDATING JumpHost #2`). A number that doesn't exist starts blank (`CREATING JumpHost #7`). It then asks for each field, with the current value in `[ ]` and the same keys as Settings. Esc at any field cancels the lot.

  | Field | ssh keyword | Notes |
  |-------|-------------|-------|
  | `host` | `Host` | The JumpHost's name, unique: letters, digits, `.`, `_`, `-`. Renaming it updates the other JumpHosts' ProxyJump. |
  | `hostname` | `HostName` | Its IP or DNS name |
  | `user` | `User` | Your username on it |
  | `port` | `Port` | Default 22 |
  | `identity_file` | `IdentityFile` | Your private key, e.g. `~/.ssh/id_ed25519_bastion`. Blank: ssh's usual keys, or a password you type. A file that isn't there is flagged, and you're asked whether to keep it. |
  | `identities_only` | `IdentitiesOnly` | Default yes: offer only that key |
  | `proxy_jump` | `ProxyJump` | Optional: another JumpHost (its name or number) this one is reached through. Only used while Chained JumpHosts is On. A loop or a missing JumpHost is refused. |
- **View a JumpHost Config** shows it as ssh config, with its route:

  ```text
  # 2. inner
  Host inner
      HostName 10.20.0.5
      User ops
      Port 22
      IdentityFile ~/.ssh/id_ed25519_inner
      IdentitiesOnly yes
      ProxyJump bastion

  Route: you -> #1 bastion -> #2 inner -> firewall
  ```
- **Test JumpHost Connectivity** checks it end to end. It first connects to the first JumpHost on the route (waiting `request_timeout`). It then logs in to the chosen one with ssh, through any ProxyJump, with every prompt turned off, and runs `exit`, waiting up to `check_timeout`. It reports `OK` or why not:
  - unreachable, or a name that doesn't resolve;
  - a host key not in your `known_hosts` yet, or one that has **changed**;
  - the key refused;
  - a password needed. The test can't type one, so it offers to try again with you typing it.
- **Delete a JumpHost** asks first. It refuses while another JumpHost's ProxyJump goes through it.
- **Chained JumpHosts** (`jump_host_chaining`, default On). Off: every JumpHost is connected to directly and ProxyJump is ignored.

### Targets

Connect to Device(s) uses the device database as it is. Only if it's empty does it load the current data file first. Firewalls that authenticate are added to it, so Write Local Data File can save them. When devices are known, they're the default:

```text
=== Targets ===
Loaded 42 firewall(s) from C:\Tools\Net_Dev_CLI\data\devices.csv. Known devices: 42.
Enter a device number from View Devices (1-42), one firewall, a comma separated list, or the path to a file with one per line (IP, hostname, or IP,hostname).
Enter connects to the 42 known device(s).
Target [known]:
```

Enter the firewalls at the `Target` prompt. The tool works out which form you used:

| You enter | Read as |
|-----------|---------|
| Enter (or `known`) | Every known device, with what the data file knows about each. The usual table and Select firewalls question follow, so you can narrow it down. |
| `7` | Device 7 from [View Devices](#main-menu). One number only; a number outside the list is refused. |
| `fw01.example.lan` | One firewall |
| `fw01.example.lan, fw02, 10.0.0.1:4443` | A list. Commas, semicolons or spaces separate the entries. |
| `C:\Users\me\firewalls.txt` | A file. Anything with `\` or `/`, a drive letter, or ending `.txt`, `.csv`, `.lst` or `.list`. Quotes from "Copy as path" are fine. |

Each entry is a hostname, an FQDN or an IPv4 address, optionally followed by `:port` (default 443). Don't include `https://`. With no known devices, the prompt offers `default_target` from the config instead, and a number is refused.

A target file has one firewall per line: its IP address, its hostname, or both separated by a comma, in either order. Blank lines, `#` comments and a header row (`name`, `hostname`, `host`, `ip` and so on) are skipped:

```text
# Production
10.0.0.1
fw02.example.lan:4443
10.0.0.3, fw03
fw04, 10.0.0.4
```

| A line with | Connects to | Hostname |
|-------------|-------------|----------|
| An IP | The IP | Read from the firewall when it connects |
| A hostname | The hostname, looked up in DNS (the IP it resolves to is shown) | Checked against the firewall's own once connected |
| Both | The IP, with no DNS lookup | Checked against the firewall's own once connected |

A `:port` can go on either value. If both have one, they have to match. A line with two IPs or two hostnames is an error. A line with more than two fields, such as a CSV export, is read as its first field, plus the second when that is the other kind of value.

The tool then prints a numbered table showing each target's IP, hostname and status. Entries that are malformed, don't resolve, or repeat an IP or hostname already in the list are reported and can't be selected. If none are usable, you're asked again.

```text
#  IP              Hostname           Status
-  --------------  -----------------  ------
1  10.0.0.1        (read on connect)  OK
2  10.0.0.2 (DNS)  fw02.example.lan   OK
3  10.0.0.3        fw03               OK
```

After that, every table has a **Firewall** column (the IP connected to) and a **Hostname** column. Messages name the firewall as `#3 fw03 (10.0.0.3)`.

Each firewall keeps its number for the rest of the session, in every table and prompt.

### Local data file

The data file is a CSV with one row per firewall. The tool keys it by **serial number**, which is always unique, unlike a hostname or an address. `config\data_template.csv` is an empty one with every column the tool knows:

```text
serial,hostname,ip,port,mgmt_ip,model,family,vm_license,sw_version,app_version,threat_version,av_version,wildfire_version,url_version,ha_enabled,ha_mode,ha_state,ha_priority,ha_running_sync,ha_peer_serial,ha_peer_hostname,ha_peer_mgmt_ip,ha_peer_state,ha_peer_model,ha_peer_sw_version,ha_peer_conn_status,last_seen,notes
```

- **What a row needs:** an IP or a hostname, so the tool can connect. Fill in as much more as you know, in any column order. Column names are matched ignoring case, and common alternatives work too (`Serial Number`, `IP Address`, `Name`, `PAN-OS`). A row with neither an IP nor a hostname is listed and left out.
- **As a target list:** once loaded (Load Local Data File, or Connect to Device(s) when nothing is loaded yet), its devices are the default target, or pick a single device by its View Devices number. You can also enter the path of any other file at the Target prompt. Any file whose first line is a header like this is read by its columns. A file without a header is read the plain way (an IP, a hostname, or both per line).
- **Checked after login:** whatever the file says is checked against what each firewall reports. The checks are the hostname, the serial number (a different serial means a different firewall now answers at that address), whether HA is on, and the HA peer's serial number. Differences are listed under **Check these firewalls**. A firewall typed at the Target prompt is matched to the data file by its IP or hostname, so it's checked too.
- **The device database:** every firewall that authenticates is stored in memory by serial number, with its system info, HA detail and when it was last seen. Each unit's `ha_peer_hostname` is filled in from its peer's own record. Run Health Check updates it too. It's held for as long as the tool runs, and never holds credentials or API keys.
- **Loading it (option 4):** replaces the device database with the file's rows. The file becomes the current data file.
- **Writing it (option 5):** asks which file (Enter takes the current one). Creates the file if it doesn't exist (an empty template if the tool knows nothing yet). An existing file is updated: rows are matched by serial number, or by IP or hostname for a row with no serial yet. The firewall's values replace the tool's columns; your `notes` column and any columns of your own are kept. Rows for firewalls not seen this run are left as they were. It shows how many rows will be added and updated, asks before writing, and keeps the old file as `<name>.bak`.

### Selecting firewalls

Wherever the tool asks which firewalls (or versions, or content types) to act on, it takes:

| You enter | Selects |
|-----------|---------|
| `3` | #3 |
| `1,4,6` | #1, #4 and #6 |
| `2-5` | #2 to #5 |
| `1,3-5,8` | Any mix of the above |
| `all` | Everything listed |
| Enter | The default shown in brackets: `[all]`, or `[none]` for anything destructive or noisy |

Entries that can't be used for that action are marked in the list, and picking one gets the reason. The question is skipped when only one can be picked. Deletes are stricter: each file has to be named by number, and `all` isn't accepted.

**Firewalls that aren't authenticated are skipped by every action, and say so.** Whether they failed, were skipped after a rejected login, or their session ended, each action starts by listing them with their reason:

```text
Skipped - not authenticated (1):
  #5 10.0.0.6: FAIL - Rejected (Invalid Credential) - wrong password, or the MFA push was denied or expired
```

They also appear at the bottom of the action's results table as `SKIPPED` with the detail `not authenticated (FAIL)` (or `EXPIRED`, `SKIPPED`), and listing tables end with a `Skipped - not authenticated:` line. This happens even when only one firewall can be picked, so a large batch never quietly drops one. Use [Retry Authentication](#9---retry-authentication) to bring them back in.

### Authentication

1. The tool asks for your username and password once.
2. For each selected firewall in turn, it generates an API key and then makes one call with it to confirm the key works. Approve each MFA push within `keygen_timeout` seconds.
3. A firewall only passes once its key has been accepted. The stage prints PASS or FAIL as it goes, including how long the keygen and the first use took.
4. The first call (`show system info`) gives each firewall's hostname, serial number, management IP, model and PAN-OS version. Each firewall that passes is also asked for its full HA detail (`show high-availability all`): its own and its peer's state, serial number, management IP, model, priority and versions. This shows as `HA_Active`, `HA_Passive` or `Standalone`, or as any other state the firewall reports, e.g. `HA_Active-Primary` or `HA_Suspended`. If the HA state can't be read, it shows `-` and nothing else is affected.
5. The tool then checks what it learned against the target list:
   - **Hostname:** a hostname given in the list has to match the firewall's own. A short name matches its FQDN (`fw03` and `fw03.example.lan`). If they differ, the firewall's own hostname is used and the difference is listed under **Check these firewalls**.
   - **The same firewall twice:** if two lines lead to the same serial number (for example its public and private IP), only the first keeps its session. The other is `SKIPPED`, so no action runs twice on one firewall.
   - **HA peers:** each HA firewall is matched to its peer in the list by the peer serial number its HA detail reports. That is checked against each firewall's reported serial number, or for one not connected, the serial in the [data file](#local-data-file). Failing that, the match is by the peer's management IP against each firewall's management IP and the IP it was listed with, so a pair reached through NAT still pairs up. A firewall whose serial is known and different never matches, whatever its IP. Hostnames are never used to pair firewalls. Also listed under **Check these firewalls**: a peer that names a different firewall as its own peer, and both units of a pair reporting `Active` (or both `Passive`).
6. It ends with a table of every firewall in the list and a count of passed, failed and skipped:

```text
#  Firewall  Hostname      Model    PAN-OS      HA          HA Peer                 Result  Notes
-  --------  ------------  -------  ----------  ----------  ----------------------  ------  -----
1  10.0.0.1  fw01-active   PA-3220  11.1.6-h14  HA_Active   #2 fw02-passive         PASS
2  10.0.0.2  fw02-passive  PA-3220  11.1.6-h14  HA_Passive  #1 fw01-active          PASS
3  10.0.0.3  fw03          PA-440   11.2.10-h3  Standalone  -                       PASS
4  10.0.0.4  fw04          PA-3220  11.1.6-h14  HA_Passive  10.0.0.5 (not in list)  PASS

Authentication: 4 passed, 0 failed
HA: 1 pair(s) in the list; peer not in the list for #4
```

**HA Peer** shows the peer's number and hostname when it's in the list, with `(not authenticated)` if its login failed. A peer that isn't in the list is shown by the management IP its partner reports, with its hostname if the device database knows that serial number. **Notes** holds the reason a firewall failed, or what to check on one that passed. The model and PAN-OS version shown are as read at login. After [Retry Authentication](#9---retry-authentication), the table is shown again for the whole list, so retried peers pair up.

Every MFA push happens in this stage, so listing, checking and later actions never stop to wait for one. On some setups, PAN-OS logs a remote (RADIUS) admin in again the first time a new key is used, which sends a second push. If it does and you ignore it, the firewall fails with "rejected on first use", and you can retry it with [Retry Authentication](#9---retry-authentication).

#### Session timeouts and the keep-alive

The goal is to authenticate once, approve MFA once, and stay connected until you disconnect or go idle.

For a remote (RADIUS) admin, the API key is tied to an admin session on the firewall, and that session ends after the firewall's admin **Idle Timeout** (`Device > Setup > Management > Authentication Settings`). The firewall's system log then shows the session timing out. After that, the same key is either refused with `Credential Expired: XXXX...XXXX has expired.`, or the next call logs the admin in again, with a new MFA push. That happens even though the username and password haven't changed. A job that was already running carries on and usually finishes; only the tool's view of it is lost.

**Keep-alive polling.** To stop sessions lapsing, a background keep-alive worker polls every authenticated firewall with `show system info` every `keepalive_interval` seconds (default 60):

- **When polling starts:** the worker starts with the authentication stage. Each firewall is polled from the moment its key works, while you approve the pushes for the rest.
- **Parallel polls:** each poll runs in its own thread, so a firewall that doesn't answer never delays the others.
- **No overlap:** a firewall that already has a request in flight, such as a check or a job status poll, is skipped for that round, because the request keeps the session open by itself. A firewall is never polled twice at once.
- **Silent:** polls are never printed or logged.
- **Setting it:** set `keepalive_interval` well below the firewall's Idle Timeout. Raise it for slow links or very large batches. `0` turns polling off.

**A failed poll is never repeated.** Repeating it is what turns one lapsed session into a stream of MFA pushes. After a failure, the firewall gets no more polls:

| Poll result | What the tool does |
|-------------|--------------------|
| Refused: `Credential Expired`, `Invalid Credential` or HTTP 403 | Drops the key, marks the firewall `EXPIRED` |
| No reply within `request_timeout` (a busy management plane, or an MFA push waiting) | Keeps the key, and stops polling until an action gets a reply from it |
| Can't reach the firewall, or any other error | Keeps the key, and stops polling until an action gets a reply from it |

Palo Firewall Management says once when a firewall's keep-alive has stopped. A slow reply doesn't end the session, so a firewall busy with a download keeps its key and its job stays watched. A lapsed session costs at most one push (from the poll, or from the next action if the poll got no reply), and Retry Authentication brings the firewall back.

**Application idle timeout.** After `app_idle_timeout` minutes (default 30) with no activity, the tool [disconnects](#disconnect): it logs out of each firewall and clears every API key and the password, with the same report as Disconnect. It applies at the Main Menu too while firewalls are connected. The next answer you type takes you back to the Main Menu. Activity means answering a prompt, or the tool sending a request to a firewall, so a long-running install or download never times out. Keep-alive polls don't count as activity. `0` never disconnects.

Polling can't stop a session that ends for other reasons: the **API Key Lifetime** running out, **Expire All API Keys**, or a management-plane restart. Whatever the reason, when a firewall reports its session has ended:

- The tool drops that firewall's key and marks it `EXPIRED`, and Palo Firewall Management says so once.
- Nothing else is sent to it, so the remaining steps for it stop with a clear reason. A job being watched is reported as "may still finish".
- **Retry Authentication** in Palo Firewall Management gets a new key, with a new MFA push.

| Reason shown | What it means |
|--------------|---------------|
| API key generated and accepted | Passed |
| Rejected (...) | The keygen got HTTP 403: wrong password, or the MFA push was denied or expired |
| Key generated, but rejected on first use | A second MFA push was denied or expired |
| No reply within Ns | The push wasn't approved in time, or the firewall's RADIUS timeout is too short |
| Management interface did not answer | Nothing listening, or a firewall rule is in the way |
| Could not connect / TLS handshake failed | The OS or TLS error, e.g. connection refused |
| Not tried after ... rejected the login | Skipped: after a rejected keygen the tool doesn't try the rest, so the same credentials can't lock the account out |

If no firewall in the session authenticates, you're back at the Main Menu, disconnected.

### Palo Firewall Management

Main Menu > Manage Devices.

```text
=== Palo Firewall Management ===
1 - List Currently Installed Content Versions
2 - List Currently Installed PAN-OS Version
3 - Manage Content Updates
4 - Manage PAN-OS Updates
5 - Config Snapshots
6 - Search Logs
7 - Run Health Check
8 - Connect via SSH
9 - Retry Authentication (1 firewall(s) not authenticated)
0 - Main Menu
```

`0` returns to the [Main Menu](#main-menu) and stays connected; Manage Devices comes back here. Option 9 only appears while a firewall isn't authenticated.

#### 1 - Installed content versions

One row per firewall with hostname, model and each content version, and a `released` row underneath with each version's release date. Columns that no firewall reports are hidden.

```text
#  Firewall    Hostname  Model    Apps & Threats  Antivirus   WildFire         URL Filtering
-  ----------  --------  -------  --------------  ----------  ---------------  --------------
1  10.0.0.1    fw01      PA-5220  9165-10321      5729-6257   1130898-1135556  20261029.20289
     released                     2026-10-27      2026-10-28  2026-10-29
```

- **Apps & Threats** is one package, so it's one column. It shows `(apps only)` when only the Apps content is installed. If the two versions differ, it shows both as `apps / threats`.
- **Dates** come from `show system info`. URL Filtering has no date, because its version already is one.

#### 2 - Installed PAN-OS version

Hostname, model, PAN-OS version, its release date and uptime per firewall. The release date comes from the firewall's cached software list, so it shows `-` until a PAN-OS update check (option 4, Check for Updates) has been run on that firewall.

#### 3 - Manage Content Updates

```text
=== Manage Content Updates ===
1 - Check for Updates
2 - Install Current Version
3 - Advanced Installation
4 - Clear Old Content Cache
5 - Delete Downloaded Content (Apps & Threats) Images
0 - Back
```

Options 2 and 3 appear once Check for Updates has run, and they work on the firewalls and content types that check covered. After an install they're hidden again until the next check, because the release lists no longer match what's installed.

**1 - Check for Updates** asks for the content types first, then the firewalls (Enter means all for both):

```text
  1) Apps & Threats
  2) Antivirus
  3) WildFire
  4) GP Client
```

For each content type, each firewall fetches the current release list from Palo Alto, which can take a while (`check_timeout`, default 120 seconds). One table per content type:

| Column | Shows |
|--------|-------|
| Installed | The installed version, with its release date underneath |
| Latest | The newest version Palo Alto lists, with its release date underneath |
| Downloaded | Whether that newest version is already downloaded to the firewall |
| Status | `Up to date`, `Update available (N newer)`, or why the check failed (e.g. no licence) |

**2 - Install Current Version** installs the newest release of each checked content type on every checked firewall that's behind. If more than one content type has an update, it shows the plan, lists those types with how many firewalls each would update, and asks which to install: one (`2`), a list (`1,3`), a range (`1-3`) or `all`. Enter installs nothing. Types you leave out show as `Skip - not selected`.

```text
  1) Apps & Threats (2 firewall(s))
  2) WildFire (2 firewall(s))
  3) GP Client (2 firewall(s))
Install - number, list (1,3) or range (2-4) [none]: 1-2
```

**Apps & Threats asks how to handle new App-IDs** whenever it's being installed, by either install option:

```text
Apps & Threats - new App-IDs in this update:
  1) Disable new apps in content update (they stay disabled until reviewed and enabled)
  2) Enable new apps (they start matching traffic as soon as the install finishes)
New apps - number [none]:
```

There's no default: Enter installs nothing. Option 1 is the same as ticking *Disable new apps in content update* in the web UI. The new App-IDs can't change which rules match existing traffic until you review and enable them (`Objects > Applications`, or `Device > Dynamic Updates > Review Apps`). Option 2 installs without the flag. The choice applies to every firewall in that install, and the plan and progress lines show `new apps disabled` or `new apps enabled`.

**3 - Advanced Installation** installs one specific version on every checked firewall. It asks for one content type (if more than one was checked), then lists every release the firewalls reported, newest first, with how many firewalls list it, have downloaded it and have it installed. Pick one by number. A version older than the installed one is marked `older than installed`, because installing it reverts the content.

Both install options then show a plan for each firewall and ask for a confirmation before sending anything:

| Action | When |
|--------|------|
| Download + install | The version isn't on the firewall yet |
| Install (already downloaded) | The file is already downloaded |
| Skip - up to date / already installed | Nothing to do |
| Skip - update check failed | The check failed on that firewall, so there's no release list to install from |
| Skip - this firewall does not list that version | Advanced Installation only |

The steps run on all the firewalls at once. Within one firewall they run in order (Apps & Threats before Antivirus, which needs a recent Apps & Threats version), and a failed step stops that firewall's later steps. Each download and install is a firewall job; the tool polls it every 10 seconds and prints its progress, up to `job_timeout` seconds (default 1800). A results table follows. Ctrl+C stops watching: jobs already started carry on on the firewall, and steps that hadn't started aren't sent.

| Content | Download | Install |
|---------|----------|---------|
| Apps & Threats, Antivirus, WildFire (current) | `<download><latest></latest></download>` | `<install><version>latest</version></install>` |
| Apps & Threats, Antivirus, WildFire (specific) | `<download><file>{filename}</file></download>` | `<install><version>{version}</version></install>` |
| GP Client | `<download><version>{version}</version></download>` | `<activate><version>{version}</version></activate>` |

With new apps disabled, Apps & Threats installs add the `<disable-new-content></disable-new-content>` flag inside `<install>`, before `<version>`. With new apps enabled, the flag is left out.

These are wrapped in each type's request path, for example `<request><anti-virus><upgrade>...</upgrade></anti-virus></request>`. HA peers aren't synced (`sync-to-peer` isn't sent), so update each peer. The tool never syncs HA config; do that by hand on the firewall.

**4 - Clear Old Content Cache** runs `delete content cache old-content` on the chosen firewalls, after one confirmation, and shows a result for each. Firewalls with a job running are skipped (see [Safeguards](#safeguards)).

**5 - Delete Downloaded Content (Apps & Threats) Images** works like [Delete Downloaded PAN-OS Images](#4---manage-pan-os-updates): one list for all the chosen firewalls, and each file to delete is named by number. The installed version isn't offered. The version a revert would go back to is marked `previous version on N, used to revert`. Deleted files are marked as no longer downloaded in this session's update check, so a later install downloads them again.

#### 4 - Manage PAN-OS Updates

```text
=== Manage PAN-OS Updates ===
1 - Check for Updates
2 - Download PAN-OS Image
3 - Clean Up PAN-OS Images
4 - Delete Downloaded PAN-OS Images
0 - Back
```

**1 - Check for Updates** has each chosen firewall fetch the PAN-OS release list from Palo Alto, so its images can be downloaded. It doesn't list the versions; it shows the installed version and whether the list was updated.

**2 - Download PAN-OS Image** asks for the firewalls, then a version. Type all or part of it:

- `11.2` matches every 11.2.x release (but not 11.20).
- `11.2.4` matches 11.2.4 and its hotfixes, such as 11.2.4-h4.
- `11.2.4-h4` matches just that release.

If exactly one release matches, it's used. If more match, they're listed with how many firewalls list, have downloaded and have installed each, and you pick one by number. If none match, the feature releases the firewalls list are shown so you can try again. The firewalls' release lists come from Check for Updates, or from each firewall's last check if you haven't run one in this session.

Before downloading, the tool shows each firewall's plan (download, or skip because the version is installed, already downloaded or not listed) and asks for a confirmation. Downloads run as jobs, the same way as content installs. Nothing is installed and nothing reboots.

**Base images.**
- **The target's base image:** a firewall moving to a new feature release needs that release's base image (e.g. 11.2.0) downloaded before PAN-OS will load a maintenance release. Without it, the download fails with `The required '11.2.0' base image must be loaded`. So when it's missing, it's always downloaded first, without asking, and the plan shows `Download 11.2.0, then 11.2.10-h16`. A firewall that doesn't list that base image is skipped, with a reminder to run Check for Updates.
- **In-between releases:** a firewall that would skip feature releases on the way (e.g. 10.2 to 11.2, passing 11.0 and 11.1) is listed with the base images it's missing. The tool offers to download those too, oldest first, for a multi-version upgrade.

PAN-OS downloads have extra safeguards, because an image is large and is written to the firewall's own disk:

- **Pre-checks**, on all the firewalls at once before the plan is shown:
  - **Running jobs:** a firewall with a job queued or running is queued: it waits for the job to finish before anything is sent (see [Safeguards](#safeguards)).
  - **Disk space for every image it will download:** base images and in-between images are counted along with the target. The numbers come from `show system disk-space`. Each image is downloaded into `/opt/pancfg`, then moved to `/opt/panrepo` while it's loaded into the software manager, before the next one starts. So `/opt/pancfg` needs room for the largest image and `/opt/panrepo` for all of them; if both are on one filesystem, it needs room for the total. If either isn't a mount of its own, the filesystem it lives on is used. The plan's **Disk after** column shows how full each would be afterwards.
  - **Not enough room:** a firewall without the room is skipped.
  - **Over 90%:** a firewall that would end up over `disk_warn_percent` (default 90%) used is listed with the figures. It's only included if you answer yes.
  - **No answer:** a firewall that doesn't answer the checks within `request_timeout` is skipped.

  Each firewall's HA state is read again too, so the pair order below is current.
- **HA pairs, one unit at a time.** When both units of a pair are in the plan, the passive unit downloads first. The active unit starts only once its peer's download has finished. If the peer's download fails, the active unit is skipped, so a problem can't take out both units of a pair.
- **A cap on parallel downloads.** At most `max_parallel_downloads` (default 10) firewalls download at once. The rest wait their turn.
- **A test group.** After the confirmation, the tool asks how many firewalls to download to first (the default comes from `download_test_group`, normally 0 = all at once). With a test group, it downloads to that many, shows their results, and asks before starting the rest.
- **Stop after failures.** Once `stop_after_failures` (default 3) firewalls have failed in a way that points at the firewall, no more are started. Those failures are a corrupt image, management that stopped responding, or no reply to the download request. The firewalls already downloading are still watched. The tool then shows the results so far and asks whether to start the rest.
- **No automatic retries.** A firewall whose download failed like that in this session is listed the next time you download, and is only included if you say so.

Failures are explained in the results:

| Result | What it means |
|--------|---------------|
| `image corrupted on the firewall's disk - check its storage, don't retry` | The firewall's own check rejected the image it stored: md5 checksum, image authentication or RPM header errors. Check the firewall's storage, and its hypervisor's, before trying again. |
| `the firewall's management stopped responding` | The firewall refused connections, returned a page that wasn't XML, or stopped answering mid-job |
| `UNKNOWN - no reply ... it may be running on the firewall, not watched` | The download request got no reply, and no job showed up on the firewall. Check its task list before trying again. |

If a download request gets no reply but a job then shows as running on the firewall, the tool watches that job instead.

**3 - Clean Up PAN-OS Images** deletes old PAN-OS images on as many firewalls as you choose. After you pick the firewalls, it asks what to keep:

```text
Keep on each firewall (the base images the kept versions need are always kept):
  1) Current and previous version (for rollback)
  2) Current version only
Keep - number [none]:
```

There's no default: Enter deletes nothing. On each firewall it then keeps these and deletes every other downloaded image:

- **The current (installed) version.**
- **The previous installed version** (option 1 only), so the last upgrade can be rolled back.
- **The base image each kept version needs**, always (e.g. 11.2.0 for 11.2.10-h8, and 11.1.0 if the previous version was 11.1.x and is kept). The firewall won't delete the installed version's base anyway.

With option 2, the previous version is deleted like any other image, so the last upgrade can no longer be rolled back from this firewall. The heading says `(current version only)` as a reminder.

The previous version comes from the firewall's revertable partition (`debug swm status`), which is what a software revert boots. If the firewall doesn't report one, the tool uses a release the firewall marks as previous, or failing that, the newest downloaded image older than the installed one (skipping base images). That last one is a guess, so it's shown as `(newest older image)`.

Each firewall gets two lines. The delete list wraps to the width of your terminal:

```text
1 - 10.0.0.12    Current: 11.2.10-h8   Previous: 11.2.7-h8   Base image: 11.2.0
    To be deleted (14, 12456 MB): 11.1.6-h14, 11.1.0, 10.2.13-h10, 10.2.13-h7, 10.2.8-h3,
                                  10.2.0, 10.1.13-h1, 10.1.5-h1, 10.1.0, 10.0.10, 10.0.0, ...
```

A kept version that isn't on the firewall is marked `(not downloaded)`. After one confirmation, the images are deleted one at a time on each firewall, and a table shows how many were deleted on each. A version the firewall lists more than once is deleted once. Before each delete, the firewall is checked for running jobs. If a delete gets no reply within `check_timeout`, the tool reads the release list before sending the next one: if the image is gone it carries on, otherwise it stops on that firewall (`STOPPED`), so two deletes never overlap.

**4 - Delete Downloaded PAN-OS Images** deletes the images you pick, rather than everything the cleanup rules allow. It lists the downloaded images on all the chosen firewalls as one list, newest first, with how many firewalls have each one. The installed version and its base image aren't offered, because the firewall won't delete them.

```text
#  Version  Size    Downloaded on
-  -------  ------  -------------
1  11.1.6   879 MB  2 of 2
2  11.1.0   879 MB  1 of 2
Delete - number, list (1,3) or range (2-4) [none]: 1,2

About to delete:
  #1 10.0.0.1: 11.1.6
  #2 10.0.0.2: 11.1.6, 11.1.0
```

Name each image by number: one (`2`), a list (`1,3`) or a range (`2-4`). Enter deletes nothing, and `all` isn't accepted. Each image is deleted on every chosen firewall that has it, after one confirmation, followed by a results table.

Checks need each firewall to have its own internet access to the Palo Alto update server.

#### 5 - Config Snapshots

```text
=== Config Snapshots ===
1 - Create Config Snapshot
2 - Download Recent Config Snapshot
3 - Download System State Backup
0 - Back
```

Every option works on as many firewalls as you choose. Downloads go to `download_folder` from `config.yml` (default `%USERPROFILE%\Downloads`).

**1 - Create Config Snapshot** saves a configuration snapshot on each firewall, named with today's date: `<YYYY-MM-DD>.xml`, the same as `save config to 2026-11-05.xml` in the CLI. The hostname isn't part of it, because the file stays on its own firewall; the hostname is added when it's downloaded. The tool shows the name and asks for a confirmation, then saves the snapshots and shows a results table. A snapshot holds the candidate configuration, so it includes any changes that aren't committed yet.

**2 - Download Recent Config Snapshot** saves each firewall's most recent snapshot as `<hostname>_<snapshot name>`, e.g. `fw01_2026-11-05.xml`.

- **Which snapshot:** the newest `<YYYY-MM-DD>.xml` created by this tool. If the firewall has none, the name with the latest date in it, e.g. `pre-upgrade_2026-11-01.xml`, downloaded as `fw01_pre-upgrade_2026-11-01.xml`. Snapshots without a date in the name, such as `running-config.xml` and `snapshot.xml`, aren't considered. If the firewall's list can't be read, the snapshot created on that firewall in this session is used.
- **File name:** the full hostname from `show system info` (or the target as you entered it, if the firewall reports none), with characters Windows doesn't allow in a file name replaced by `-`. Hostnames are unique, so files from different firewalls don't collide.
- **Listing:** the list comes from the XML API's `complete` action on `show config saved` (the CLI's Tab completion).
- **Download:** the file comes from `<show><config><saved>{name}</saved></config></show>`.
- **Existing files:** a file of the same name already in the folder isn't overwritten. The new one is saved as `name (1).xml`, `name (2).xml` and so on, which normally only happens when the same snapshot is downloaded twice.
- **Results:** a table shows the snapshot and file name for each firewall, followed by the folder.

**3 - Download System State Backup** exports each firewall's device state (`type=export&category=device-state`) and saves it as `<hostname>_<YYYY-MM-DD>_device-state.tgz`. The device state holds the configuration plus settings pushed from Panorama, certificates and keys, so it's what you need to rebuild a Panorama-managed firewall. A file that doesn't start like a `.tgz` is still saved, but marked `DONE (not gzip)` so you can check it. Existing files are never overwritten, as above.

Both downloads contain the firewall's full configuration, including password hashes and encrypted keys, so keep them somewhere safe.

#### 6 - Search Logs

Searches one log type on the firewalls you pick and merges what they return into one timeline.

```text
=== Search Logs ===
1 - Traffic
2 - Threat
3 - URL Filtering
4 - WildFire
5 - Data Filtering
6 - Config
7 - System
8 - HIP Match
9 - GlobalProtect
10 - User-ID
11 - Authentication
12 - Decryption
13 - IP-Tag
0 - Back
```

After picking a log type and the firewalls, it asks for:

- **Query:** the web UI's filter syntax for that log type, sent to the firewall as it is. The prompt shows examples for the log type picked (below), plus `( receive_time geq '2026/11/14 08:00:00' )`, which works for all of them. Blank searches everything. The last query for that log type is offered next time: Enter reuses it, Del clears it, Esc cancels.
- **Entries per firewall:** default 20, up to 5000.

| Log type | Query examples shown |
|----------|----------------------|
| Traffic | `( addr.src in 10.1.1.5 ) and ( port.dst eq 443 ) and ( action eq deny )` |
| Threat | `( severity geq high ) and ( subtype eq vulnerability )` |
| URL Filtering | `( url contains 'example.com' ) and ( action eq block-url )` |
| WildFire | `( category eq malicious )` |
| Data Filtering | `( addr.src in 10.1.1.5 ) and ( action eq deny )` |
| Config | `( admin eq jsmith ) and ( cmd eq set )`, `( path contains 'rulebase' )` |
| System | `( severity geq high )`, `( subtype eq ha )`, `( description contains 'commit' )` |
| HIP Match | `( machinename eq LAPTOP01 )`, `( matchname eq 'Corp-Compliant' )` |
| GlobalProtect | `( eventid eq 'portal-auth' ) and ( status eq 'failure' )`, `( eventid eq gateway-auth )` |
| User-ID | `( user eq 'corp\jdoe' )`, `( ip eq 10.1.1.5 )` |
| Authentication | `( user eq 'corp\jdoe' )`, `( authpolicy eq 'MFA-Policy' )` |
| Decryption | `( sni contains 'example.com' )`, `( addr.dst in 10.1.1.5 )` |
| IP-Tag | `( tag_name eq quarantine )`, `( ip eq 10.1.1.5 )` |

Each firewall runs the search as a log job (`type=log`, newest first), which the tool checks every 2 seconds until it's finished. A job that hasn't finished within `check_timeout` is stopped (`action=finish`), and that firewall is reported as failed.

```text
Time                 Device  Source    Src Zone  Src Port  Destination  Dst Zone  Dst Port  App  Action  Rule
-------------------  ------  --------  --------  --------  -----------  --------  --------  ---  ------  ------
2026/11/15 09:00:07  site-b  10.1.1.5  trust     50000     8.8.8.8      untrust   443       ssl  allow   core-b
2026/11/15 09:00:05  site-a  10.1.1.5  trust     50000     8.8.8.8      untrust   443       ssl  allow   out-a
```

- **One timeline.** Entries from every firewall are merged newest first by each entry's own timestamp (`time_generated`), so you can follow traffic through several devices. Firewalls whose clocks differ will interleave out of step.
- **Summary columns.** Source and destination (address, zone, port), application, action, rule and the device the entry came from. Log types without those show their own fields instead: severity, event and description for System; admin, command and path for Config; and so on. Long values are cut to 60 characters.
- **CSV.** It then offers to save every entry, with every field the firewall returned, to `<download_folder>\<date>_<time>_<log type>_logs.csv`.
- **Run log.** The entries aren't written to the run log, only a one-line summary (log type, query, count, failures) and the CSV's path.
- **Permissions.** The admin role needs **XML API > Log** permission. A firewall that refuses says so.

#### 7 - Run Health Check

Runs every check that's turned on in `health_checks.yaml`, on all the firewalls you pick at once, and reports what needs an engineer's attention. The checks are read-only. It replaces HA Status Validation: the HA check reads each unit's HA state, and the HA pairs table follows the report. A pair that isn't synchronized is reported; syncing it is done by hand on the firewall.

```text
=== Health Check ===
Running 16 checks on 5 firewall(s)...

#  Firewall  Hostname  Result  FAIL  WARN  ERROR  Needs attention
-  --------  --------  ------  ----  ----  -----  ---------------------------------------
1  10.0.0.1  fw1       WARN    0     2     -      HA
2  10.0.0.2  fw2       FAIL    2     3     -      Chassis LEDs, Environmentals, HA
3  10.0.0.3  vm3       FAIL    4     3     -      MP Resources, Disk, Licenses, Interfaces
4  10.0.0.4  fw4       ERROR   0     0     2      Chassis LEDs, Connection
5  10.0.0.5  fw5       PASS    0     0     -      -

What failed, and what to do about it:

#3 vm3 (10.0.0.3) - FAIL
  FAIL   MP Resources: management memory 95%
           > show system resources: look for a process using a lot of memory. A process (or firewall)
             restart may be needed - check with TAC first.
  FAIL   Disk: /opt/panrepo 74% used, 2.0 GB free (under 3 GB)
           > Free space: Delete old PAN-OS images and content (Manage PAN-OS Updates / Manage Content
             Updates), old config snapshots and tech-support files.
  WARN   Interfaces: ethernet1/2.100 down (zone dmz, 10.2.0.1/24, vr:default)
           > Check the cable, the transceiver and the switch port - or, if it's meant to be down, add it
             to interfaces_ignore.
...
Health check: 2 FAIL, 1 ERROR, 1 WARN, 1 PASS
```

- **Result** is the firewall's worst finding: `FAIL`, then `ERROR` (a check couldn't run), then `WARN`. `PASS` means every check passed or didn't apply.
- **The details** list each `FAIL`, `ERROR` and `WARN` with what was found and what to do about it, worst first.
- **ERROR** means a command failed. The rest of the checks still run, unless the firewall stops answering or its session ends. When the reply says permission was refused, it names the XML API permission the admin role needs.
- **N/A** means a check doesn't apply: chassis LEDs and sensors on a VM-Series, HA on a standalone firewall, Panorama on an unmanaged one.
- **The results file** (`<log name>_<HHMMSS>_health-check.csv`, next to the run log) has every result, `PASS` and `N/A` included, with the remediation text.
- **Times** (the System log window and job ages) use the firewall's own clock, from `show system info`.

| Check | Reads | WARN (default) | FAIL (default) |
|-------|-------|----------------|----------------|
| System Info | `show system info` | Uptime under 24 h; device certificate not Valid | VM-Series with no VM license |
| Chassis LEDs | `show system state filter chassis.leds` (hardware only) | - | An LED red or amber, or the alarm LED on. The `ha` LED is left out: it's amber on a passive unit. |
| Environmentals | `show system environmentals` (hardware only) | A power supply slot empty; a temperature within 5 C of its maximum | A temperature, fan or power sensor in alarm |
| MP Resources | The management CPU 1-minute average (`show system state filter sys.monitor.s0.mp.exports`) and `show system resources` | CPU 70%; memory 85% (not counting buffers and cache); swap 1% | CPU 80%; memory 90% |
| Dataplane | `show running resource-monitor minute last 5` | CPU 80% (average of the cores); packet buffer or descriptors 50% (highest minute of the average) | CPU 90%; packet buffer or descriptors 80% |
| Sessions | `show session info` | 80% of the session table | 90% |
| HA | `show high-availability all` | HA2 or a backup link down; config not synchronized; a version doesn't match the peer's (`*-compat` Mismatch) | Not active or passive (suspended, non-functional...); both units active; peer not connected; HA1 down |
| Interfaces | `show interface all` | An interface (or subinterface) with a zone, IP or virtual router configured whose port is down. Tunnel, loopback, VLAN, HA and management interfaces aren't checked. | - |
| System Log | System log, `( severity geq high )` over the last 24 h | 1 or more high | 1 or more critical |
| Log Forwarding | `show logging-status` | Logs aren't being forwarded to Panorama, a Log Collector or the logging service | - |
| Panorama | `show panorama-status` | - | A configured Panorama not connected |
| Licenses | `request license info` (the installed licenses; nothing is fetched) | 30 days or fewer left | Expired |
| Disk | `show system disk-space` | A partition 85% full | 95% full; `/opt/panrepo` under 3 GB free. `/opt/panlogs` is left out: it runs full by design. |
| Pending Changes | `check pending-changes` | Uncommitted changes in the candidate config | - |
| Jobs | `show jobs all` | A job failed in the last 24 h; a job still running after 60 minutes | - |
| Certificates | The certificates in the firewall's own config (`/config/shared/certificate` and each vsys) | 30 days or fewer left | Expired |

Every threshold, severity and on/off switch is in [health_checks.yaml](#health-check-thresholds).

- **MP CPU** is never taken from `top`'s `%Cpu(s)` line: on models whose dataplane shares the CPU, `pan_task` busy-polls its cores and `top` reads 80-100% on an idle firewall. If the 1-minute average isn't reported, CPU isn't judged (`CPU not read`) and the reply is written to the run log.
- **Licenses:** a renewal leaves the expired entry next to the new one, so each feature is judged by its latest expiry.
- **Log Forwarding** doesn't see syslog servers. Turn it off for firewalls that only log locally or to syslog.
- **Certificates** come from the firewall's own config. Certificates pushed from a Panorama template may not be in it.
- **Not verified on a live firewall yet:** the `ifnet` field names in `show interface all`, the `chassis.leds` and `show logging-status` text formats, and the `sys.monitor.s0.mp.exports` CPU figure.

##### HA pairs

After the report, the HA pairs among the chosen firewalls, from the states the HA check just read:

```text
#  Unit 1          Unit 2                    HA State          Peer Link  Config Sync       Versions
-  --------------  ------------------------  ----------------  ---------  ----------------  ----------------------
1  #1 fw01-active  #2 fw02-passive           Active / Passive  up         Not synchronized  PAN-OS 11.1.6 / 11.1.4
2  #4 fw04         10.0.0.5 (not in list)    Passive / Active  up         Not synchronized  Match

Standalone: #3 fw03
```

- **Pairs** are matched the same way as at [authentication](#authentication): by serial number, or by management IP. If a firewall's peer is connected in this session but you didn't pick it, it's read too. A peer that's in the list but not authenticated shows as `#5 fw05 (not authenticated)`. A peer that isn't in the list at all shows as `(not in list)`, using what its partner reports about it. Pairing problems, such as a peer naming a different firewall or both units `Active`, are listed under **Check these HA pairs**.
- **Unit 1** is the active unit, or active-primary in an active/active pair.
- **HA State** is each unit's state as reported: `Active / Passive`, `Active-Primary / Active-Secondary`, `Active / Suspended`, `Passive / Non-Functional` and so on.
- **Config Sync** is the running-config sync status: `Synchronized`, `Not synchronized` or whatever the firewall reports.
- **Versions** compares the two units' PAN-OS, Apps & Threats and Antivirus versions. It shows `Match`, or each difference.

#### 8 - Connect via SSH

Opens an SSH session to one firewall in the tool's window, with Windows' built-in OpenSSH client (`C:\Windows\System32\OpenSSH\ssh.exe`), directly or through a [JumpHost](#jumphosts). Type `exit` on the firewall to come back to Palo Firewall Management.

```text
=== Connect via SSH ===

  #1 fw1-edge.example.lan (10.0.1.7)  (password filled in)
  #2 fw2-edge.example.lan (10.0.1.8)  (you type the password - not authenticated: FAIL)
Connect to - number [none]: 1
Use a JumpHost? [y/N]: y

#  Host     HostName             User  Port  IdentityFile                 ProxyJump
-  -------  -------------------  ----  ----  ---------------------------  ---------
1  bastion  bastion.example.com  ops   22    ~/.ssh/id_ed25519_bastion    -
JumpHost - number [none]: 1
```

- **One firewall at a time.** Every firewall is listed, authenticated or not; pick one by number. Enter connects to nothing.
- **Login.** ssh connects to the same address the API uses (without the HTTPS port), as the username you authenticated with. Approve the MFA push if your login sends one.
- **JumpHosts.** The JumpHost question is only asked when some are set up (Settings > Application Settings > JumpHosts). For each session, the tool writes every JumpHost to a temporary ssh config file and runs `ssh -F <that file> -J <JumpHost> ...`. The file has no passwords and is deleted when the session ends. Your own `~/.ssh/config` is still read, after the JumpHosts. Anything a JumpHost asks for (its password, a key passphrase) you type.
- **The password is filled in** for a firewall that accepted it at authentication. A firewall that rejected or skipped the login is never sent it, so it can't count towards an account lockout: ssh asks you to type it there.
- **How it's filled in.** ssh only takes a password from a program, so it runs the tool's EXE a second time (`SSH_ASKPASS`). That copy fetches the password once over a local named pipe that only your account can open, protected by a random key for that session. It only does that for a prompt naming the firewall (`admin@10.0.1.7's password:`), so a JumpHost's prompts never get it. The password never goes on a command line, in an environment variable or on disk, and the pipe closes once it's been handed over: if ssh asks again (a wrong password, or an MFA code), you type it.
- **Host keys are checked as ssh always does**, against your own `known_hosts`, JumpHosts included. The first time you connect to a firewall, ssh shows its key fingerprint and asks whether to continue; check it before answering `yes`. The tool never turns that check off.
- **Filling in needs the EXE and OpenSSH 8.4 or later** (Windows 11 has 9.5). Run from source, or with an older client, ssh asks for the password and everything else works the same.
- While the session is open, the [application idle timeout](#session-timeouts-and-the-keep-alive) waits, the keep-alive carries on, and Ctrl+C goes to the firewall's CLI, not the tool. The run log records that the session started and ended, but not what happened in it.

#### 9 - Retry Authentication

Only shown while at least one firewall has no API key: it failed, was skipped, or its session ended. The count in the label is worked out each time Palo Firewall Management is shown, so it follows failures, expiries and retries.

It lists the firewalls that need authenticating and lets you pick one or more (Enter means all of them). It asks for your username and password again and runs the [authentication stage](#authentication) on just those firewalls, with an MFA push for each. The question is skipped when only one firewall needs it.

#### Safeguards

**Jobs already running.** Nothing that changes a firewall is sent while it has a job queued or running. That covers deletes, cache clears, PAN-OS and content downloads, and content installs. Jobs started from this tool, the web UI or Panorama all count, including routine ones such as `EDLFetch`. The tool reads `show jobs all` on the firewalls in parallel before asking for the confirmation.

- **Downloads and content installs wait in a queue.** A firewall with a job running is marked in the plan:

  ```text
  17  10.0.1.7  fw1-edge.example.lan  10.2.13-h7  /opt/panrepo 9%  Queue - wait for job 190565 (EDLFetch, running), then: Download 11.2.0, then 11.2.10-h16
  ```

  After the confirmation it's checked again every minute. Its download starts once nothing is running, or it's skipped if the job is still running after `queue_timeout` (default 30 minutes). `queue_timeout: 0` skips busy firewalls straight away, as before. A queued firewall doesn't take a parallel-download slot while it waits.
- **Every step is checked.** Before each step after a firewall's first (e.g. the target image after its base image), the firewall is checked again. A job that started in between makes that step wait in the queue the same way. The first step is checked again too if more than a minute has passed since the pre-check.
- **Deletes and cache clears skip a busy firewall** instead of waiting. Every single delete is checked first.
- **A firewall that doesn't answer the check, or whose check fails, is skipped**, never queued.
- **Read-only actions aren't blocked:** checks, listings, and snapshot and system state downloads.

**Results files.** Every action that changes firewalls saves its results table as a CSV file next to the run log, with each firewall's hostname, HA state and HA peer (see [Run logs](#run-logs)). It's ready to attach to a support case.

#### Delete commands

The delete commands, from the firewall's API browser, are in `DELETE_COMMANDS` at the top of `palo_image_updater.py`. The firewall's reply to each delete is printed.

| Action | XML |
|--------|-----|
| Clear old content cache | `<delete><content><cache><old-content></old-content></cache></content></delete>` |
| Delete a PAN-OS image | `<delete><software><version>{version}</version></software></delete>` |
| Delete a content update file | `<delete><content><update>{filename}</update></content></delete>` |

Antivirus and WildFire files aren't offered for deletion, because those use separate delete commands.

## Credentials and API keys

- The password is read with `getpass`. Once a firewall accepts it, it's kept in memory for [Connect via SSH](#8---connect-via-ssh) until you [disconnect](#disconnect) (Disconnect, Exit, Ctrl+C, or the idle timeout). Going back to the Main Menu keeps it. If no firewall accepts it, it's dropped straight away. Retrying asks for it again.
- Credentials go in the POST body, never in a URL.
- API keys are held only in memory. Disconnect logs each one's admin session out on the firewall and clears them, and it also runs when you exit (including Ctrl+C and closing the window).
- Nothing is written to disk except `config/config.yml` and `config.yml.bak`, which hold no secrets (JumpHosts name a key file, never a key or password), the temporary ssh config written for a JumpHost session (deleted when it ends), the [run logs](#run-logs), the [local data file](#local-data-file) when you write it (firewall details only, never credentials or keys), and the config snapshots and system state backups you download. Those downloads are the firewall's full configuration, including password hashes and encrypted keys, so keep them safe.
- The run logs record the username and every answer you type, but never the password (it's read with `getpass`, which bypasses the log) or the API keys.

## Run logs

Every run writes a log file, `<log_folder>\<YYYY-MM-DD_HHMMSS>.log`, with everything shown on screen and every answer you typed, each line timestamped:

```text
2026-11-05 11:24:57  === Palo Firewall Management ===
2026-11-05 11:24:57  1 - List Currently Installed Content Versions
...
2026-11-05 11:24:59  Choice: 6
```

The password prompt appears as `Password: (not logged)`. The tool prints the log's path when it starts.

Each action that changes firewalls (installs, downloads, deletes, cache clears), and each health check, also saves its results table as `<log name>_<HHMMSS>_<action>.csv`, e.g. `2026-11-05_121501_201525_pan-os-download.csv`. It has one row per firewall: time, number, firewall, hostname, HA state, result and the full detail, including skipped firewalls and why.

At start-up, logs and results files older than `log_retention_days` are deleted. Only files named like the tool's own logs are touched, so anything else you keep in that folder is left alone. If the log folder can't be written to, the tool says so and carries on without a log.

## Configuration options

`config/config.yml` is created from `config/skeleton_config.yml` on first run. A missing option uses its default. Settings > Application Settings edits every option except `jump_hosts` (that's Settings > Application Settings > JumpHosts), and adds an option the file doesn't have yet at the end.

| Option | Default | What it does |
|--------|---------|--------------|
| `default_target` | `''` | Offered at the Target prompt when no devices are known: one firewall, a list, or a file path |
| `verify_ssl` | `false` | Certificate checking: `false`, `true`, or the path to a CA bundle |
| `keygen_timeout` | `90` | Seconds to approve the MFA push |
| `request_timeout` | `30` | Seconds to wait for any other API call, and for ssh to connect to a JumpHost |
| `check_timeout` | `120` | Seconds to wait for an update check, a snapshot, a system state export, a log search or a JumpHost test |
| `job_timeout` | `1800` | Seconds to wait for each download or install job |
| `job_poll_interval` | `10` | Seconds between job status checks |
| `keepalive_interval` | `60` | Seconds between keep-alive polls of every authenticated firewall; `0` turns polling off |
| `app_idle_timeout` | `30` | Minutes with no activity before the tool disconnects (logs out and clears the keys) and returns to the Main Menu; `0` never disconnects |
| `download_folder` | `%USERPROFILE%\Downloads` | Where snapshots, system state backups and log search CSVs are saved |
| `log_folder` | `logs` | Where run logs are written |
| `log_retention_days` | `30` | Logs older than this are deleted at start-up; `0` keeps them all |
| `max_parallel_downloads` | `10` | Most firewalls downloading a PAN-OS image at once; `0` = no limit |
| `disk_warn_percent` | `90` | Disk use a PAN-OS download may bring `/opt/pancfg` or `/opt/panrepo` up to before you're asked whether to include the firewall; `0` skips the disk check |
| `queue_timeout` | `1800` | Seconds a download or content install waits for a firewall's running jobs to finish; `0` skips a busy firewall instead |
| `data_file` | `data\devices.csv` | The [local data file](#local-data-file) that Load and Write offer until another is loaded or written, and that Connect to Device(s) loads when the device database is empty |
| `stop_after_failures` | `3` | Serious download failures (corrupt image, management lost, no reply) before no more are started; `0` never stops |
| `download_test_group` | `0` | Default answer to the test group question before a PAN-OS download; `0` = all at once |
| `jump_host_chaining` | `true` | Follow each JumpHost's `proxy_jump` (Chained JumpHosts); `false` connects to every JumpHost directly |
| `jump_hosts` | `{}` | The numbered [JumpHosts](#jumphosts): `host`, `hostname`, `user`, `port`, `identity_file`, `identities_only`, `proxy_jump` |

Numbers are checked when the tool starts. A value that isn't a number uses the default, and one out of range (e.g. a negative `job_poll_interval`) is brought into range, with a warning.

In `download_folder`, `log_folder` and `data_file`, environment variables (`%USERPROFILE%`, `%ONEDRIVE%`...) and `~` are expanded. A relative path is relative to the tool's folder, or the EXE's folder for the standalone EXE.

### Health check thresholds

`config/health_checks.yaml` is created from `config/skeleton_health_checks.yaml` the first time it's needed. It's laid out like `config.yml`: one `key: value` per line, grouped by check, with comments. Settings > Health Check Thresholds edits it (keeping your comments), or edit it by hand: it's read again at the start of every health check. A missing or bad value uses the default, with a warning.

- **`<check>_enabled`** turns a check on or off, e.g. `log_forwarding_enabled: false`.
- **Number thresholds** come in pairs: `_warn` and `_fail`, e.g. `mp_resources_memory_warn: 85` and `mp_resources_memory_fail: 90`. `0` turns that threshold off.
- **Severity settings** say what a condition is: `warn`, `fail` or `off`, e.g. `interfaces_down: warn`, `ha_config_sync: warn`, `panorama_disconnected: fail`.
- **Lists** are written `[a, b]`: `system_log_exclude_eventids` (event IDs not counted, as known noise), and the `_ignore` lists for chassis LEDs, interfaces, licenses, partitions and certificates.
- **Windows:** `system_log_hours: 24` and `jobs_hours: 24`.

Clearing the key from the tool doesn't revoke it on the firewall. PAN-OS keys stay valid until the firewall's **API Key Lifetime** expires them (`Device > Setup > Management > Authentication Settings`; the default of 0 means never), you click **Expire All API Keys**, or the account's password changes. Setting a lifetime of a few hours is a good idea.

## Firewall-side MFA setup

The keygen call is a single username and password request, so MFA has to be a push that the RADIUS server sends on its own (Duo, Okta or Entra through NPS). The firewall waits for the RADIUS reply while you approve the push. Its settings need to allow for that:

- **RADIUS server profile timeout:** the default is 3 seconds with 3 retries. Raise the timeout above the time it takes to approve a push (30–60 seconds) and set retries to 1, or a slow approval fails and each retry can send another push.
- **SAML admins:** the XML API can't use SAML. If the web UI uses SAML, PAN-OS 10.2+ can give non-UI access (API and CLI) a separate RADIUS authentication profile.
- **keygen_timeout** in `config.yml` should be a little longer than the firewall's RADIUS timeout.

The tool never retries a request or follows a redirect. **Extra pushes for one login** come from the firewall sending more than one RADIUS request. Check these in order (`Device > Server Profiles > RADIUS`, then `Device > Authentication Profile`):

1. **Authentication Protocol set to Auto.** The firewall tries protocols in turn until one works, and each attempt is a new RADIUS request and a new push. Set it to the protocol your RADIUS server uses (usually PAP for a Duo Authentication Proxy).
2. **Timeout and retries.** Each retry after the timeout is a new push. Use a 30–60 second timeout and 1 retry.
3. **More than one server in the profile.** If the first doesn't answer before its timeout, the firewall asks the next one, which sends another push.
4. **An authentication sequence** that lists two profiles backed by the same RADIUS/MFA service.

The seconds shown next to each result help tell these apart. `Monitor > Logs > System`, filtered on `( subtype eq auth )`, shows each RADIUS attempt the firewall made.

## Project Structure

```text
palo-toolkit/
├── config/
│   ├── config.yml              # Your configuration (not in repo)
│   ├── config.yml.bak          # The copy before the last Settings change (not in repo)
│   ├── data_template.csv       # Empty data file with every column
│   ├── health_checks.yaml      # Your health check thresholds (not in repo)
│   ├── health_checks.yaml.bak  # The copy before the last threshold change (not in repo)
│   ├── skeleton_config.yml     # Configuration template
│   └── skeleton_health_checks.yaml  # Health check thresholds template
├── data/
│   └── devices.csv             # Your local data file (not in repo)
├── dist/
│   └── Net_Dev_CLI.exe  # Built by build_exe.ps1 (not in repo)
├── logs/                       # Run logs (not in repo)
├── .gitlab-ci.yml              # GitLab SAST and secret detection (used when the repo is on GitLab)
├── build_exe.ps1               # Builds the standalone EXE with PyInstaller
├── palo_image_updater.py       # The tool
└── pyproject.toml
```
