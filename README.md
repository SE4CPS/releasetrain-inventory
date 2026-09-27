# releasetrain-inventory

A stdlib-only Python package that scans the local machine for installed
**software** (not OS/library packages) and prints each one's name and
version to the terminal.

## Install

```
pip install releasetrain-inventory
```

Also installable from source (`pip install .` from a local clone) or straight
from GitHub (`pip install git+https://github.com/SE4CPS/releasetrain-inventory.git`).

Installing gives you the `releasetrain-inventory` command; `python -m
releasetrain_inventory` works the same way without needing a console-script
shim on `PATH` (useful right after a `pip install --user` on Linux, where
pip warns the script directory isn't on `PATH` yet).

## Usage

```
releasetrain-inventory [options]
```

| Flag | Effect |
|---|---|
| `--json` | print a JSON array instead of a table |
| `--filter TEXT` | only show names containing TEXT (case-insensitive) |
| `--sort {name,version,publisher}` | sort key (default: `name`) |
| `--reverse` | reverse the sort order |
| `--limit N` | show at most N results |
| `--no-header` | omit the table header row |
| `-o, --output FILE` | also write the output to FILE |
| `--all` | also include entries with no detected version (shown as `-`); hidden by default |
| `--include-packages` | Linux only: also list manually-installed OS packages (apt/dnf/pacman); off by default |
| `--exec-version` | Linux only: last resort, run an app's own `--version` when its package can't supply one; off by default since it executes the binary |
| `--no-os` | don't include the operating system itself as an entry; included by default |
| `--dev-tools` | also check well-known CLI runtimes/services on `PATH` (see below); off by default since it executes each one found |
| `-v, --verbose` | print scan diagnostics to stderr |
| `--version` | print the installed package version and exit |

### The operating system itself, and CLI runtimes/services

Neither of these fit the "installed software" model the rest of this tool
uses (a package, an app bundle, a desktop launcher), so they're handled as
two small, separate additions:

- **The OS itself** (`--no-os` to turn off) — included as one entry by
  default: `Windows 11 Pro` / `macOS` / whatever `/etc/os-release`'s `NAME`
  says on Linux, with its real version. This is what most people expect
  "installed software" to include and none of the other scans produce it.
- **`--dev-tools`** — a fixed, curated list of well-known CLI runtimes and
  services checked via `shutil.which` + their own `--version`/`-v`, since
  none of them have a desktop entry, a Windows Uninstall key, or necessarily
  even an OS package (installed via `nvm`, a language's own installer, a
  static binary, `docker`'s own install script, ...). This is most useful on
  a Linux server, where a plain scan finds nothing at all beyond
  `--include-packages`. Current list: `node`, `npm`, `python3`, `python`,
  `git`, `nginx`, `apache2`/`httpd`, `mysql`, `psql`, `redis-server`,
  `docker`, `java`, `go`, `ruby`, `php`, `rustc`, `dotnet`.

## Uploading to your ReleaseTrain account

`--upload` sends whatever the current filters/sort/limit are showing to your
account's Installed versions (Account page > Installed versions), merging
with what's already saved unless `--no-merge` is given.

```
releasetrain-inventory --upload --email you@example.com
```

| Flag | Effect |
|---|---|
| `--upload` | upload the currently-shown results |
| `--email EMAIL` | account email (or set `RELEASETRAIN_EMAIL`) |
| `--token TOKEN` | use this token instead of logging in (or set `RELEASETRAIN_TOKEN`) |
| `--map-file FILE` | JSON `{"scanned name": "ReleaseTrain component"}` overrides (default `~/.releasetrain/component-map.json`) |
| `--strict-match` | only upload entries that matched a tracked component name; drop unconfirmed guesses instead of uploading them |
| `--machine LABEL` | label for this computer (default: auto-detected hostname + OS, remembered in `~/.releasetrain/machine.json`) |
| `--no-machine` | don't tag uploaded entries with a machine label |
| `--no-merge` | replace your saved list instead of merging with it |
| `-y, --yes` | skip the confirmation prompt |
| `--dry-run` | show what would be uploaded without contacting the server |

**The password is never a CLI argument** (it would sit in shell history and
be visible to other local processes via `ps`). If `--token`/`RELEASETRAIN_TOKEN`
isn't set, the password comes from `RELEASETRAIN_PASSWORD` or a hidden
`getpass` prompt. A successful login's token is cached at
`~/.releasetrain/token.json` (mode `600`) so later runs don't need to
re-enter credentials until it expires.

### Vendor and machine, not just component + version

Each uploaded entry can carry two more, optional fields (the server accepts
and stores both, and the Account page's Installed versions list displays and
lets you edit them):

- **`vendor`** — the cleaned publisher name (e.g. `Google`, `VMware`),
  derived from the scanned `Publisher` field. ReleaseTrain itself only
  tracks a bare product name with no publisher field of its own, so this
  isn't "matched" against anything on ReleaseTrain's side — it's just
  recorded alongside the component so a name that couldn't be confidently
  matched to a tracked component (see below) still says *whose* it is,
  instead of, say, a bare, ambiguous `Host`.
- **`machine`** — a label for the computer this was scanned on (default:
  auto-detected `hostname (OS)`, e.g. `DESKTOP-ABC123 (Windows 11)`,
  remembered across runs; override with `--machine "Work Laptop"`). This
  matters the moment you run the scanner on more than one computer: the
  same component (`node`, say) at two different versions on two machines
  is recorded as two separate rows instead of one overwriting the other.
- **`recordedAt`** — when *this* row's version was actually captured: one
  timestamp shared by every entry in a given run, set fresh each time you
  scan and upload. Shown in the Account page as "recorded Xh ago". This is
  distinct from the drift row's own "checked Xh ago" stamp, which is when
  ReleaseTrain last saw the *latest* release for that component, not when
  your own snapshot was taken.

Both fields are part of each entry's uniqueness key, both on upload and in
the account UI: an entry is now identified by **(component, vendor,
machine)** together, not component alone, so "Host" from one vendor no
longer clobbers "Host" from another, and the same component on two of your
machines can coexist.

### Why component names need matching, not just uploading as-is

ReleaseTrain tracks a bare product name only (e.g. `Chrome`, `VirtualBox`)
and matches your saved entries against it case-insensitively, exact string
only — there's no separate publisher/vendor field on ReleaseTrain's side to
map a `Publisher` value onto. A local scan's name is rarely that bare,
though: the vendor is often baked into the product name itself ("Oracle
VirtualBox 7.2.16"), or sits only in `Publisher` while the product name
never had it ("Microsoft Edge" already needs no stripping, but many others
do). So the fix isn't mapping `Publisher` to anything on ReleaseTrain — it's
using `Publisher` to recognize and strip the vendor prefix off the product
name (tolerating typos on either side, e.g. a `Publisher` of "Mircosoft
Cooperation" still strips as "Microsoft"), then matching whatever's left:

1. **Your map file** — an exact override you maintain, checked first.
2. **Exact match** against `/api/c/names` (case-insensitive).
3. **Normalized match** — vendor prefix and version/edition noise stripped,
   then compared again.
4. **Fuzzy match** — a close (but not exact) match against a tracked name.
5. **Unmatched** — uploaded under the **original scanned name** (not the
   stripped guess, which is shown only for diagnostics) so a name that
   didn't actually confirm against anything stays self-explanatory (e.g.
   `VMware Host`, `vendor: VMware`) instead of collapsing to an ambiguous
   bare `Host`. Listed in the summary so you can add a `--map-file` entry
   if you'd still rather it use a different component name.
   `/api/c/names` only returns *recently active* components, so plenty of
   legitimate software will land here just because ReleaseTrain hasn't
   tracked a release for it lately — pass `--strict-match` if you'd rather
   drop those than upload an unconfirmed one.

## How it finds "software," not packages, per OS

- **Windows** – reads the registry's `...\Uninstall` keys (the same source
  Settings > Apps reads from), skipping hidden system-component/update
  entries.
- **macOS** – reads `.app` bundles under `/Applications`,
  `/System/Applications`, and `~/Applications`, taking the version from each
  bundle's own `Info.plist`.
- **Linux** – there's no OS-wide "installed software" registry, so it reads
  desktop launcher entries (`*.desktop` under `/usr/share/applications`,
  `/usr/local/share/applications`, `~/.local/share/applications`) and
  resolves each one's version through the single package that owns its
  executable. This is a targeted, one-app lookup, not a bulk package-manager
  dump; pass `--include-packages` if you also want the packages you
  explicitly asked to install (not their dependencies).

No third-party dependencies; only the Python standard library is used.

## Development

```
pip install -e .          # editable install, picks up source edits immediately
python -m pyflakes src/releasetrain_inventory/*.py
```

The package lives under `src/releasetrain_inventory/` (`cli.py` holds all the
logic; `__main__.py` just wires up `python -m releasetrain_inventory`).
