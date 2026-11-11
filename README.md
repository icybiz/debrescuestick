# DebRescueStick

A Debian-based USB rescue environment with SSH access through your own public
key. The short network name is **debrstick.local**. Website:
[eorls.com/debrescuestick](https://eorls.com/debrescuestick/).

The public website is being rebuilt through the ordinary EORLS customer editor.
The native `site.json` draft contains the English, German, French and Spanish
content and layout, with operator-specific details left empty. The general image
service integration is not yet available in the EORLS editor; the old standalone
HTML frontend is no longer served as the EORLS project page. The image backend and
its exact Debian sources are retained. See [API.md](API.md) for the existing public
service contract and deployment limitations. This source revision adds optional
24-hour request-key recovery, tested against a real fast-worker ZIP in isolated
final staging. The running backend must be upgraded before an adapter enables
that extension; image/download lifetime remains two hours. Do not reinstall the old
frontend or its broad reverse-proxy route over an EORLS customer website.

This repository contains the complete original project software: the website,
HTTP backend, queue, image builder, boot scripts, deployment and qualification
tools, and automated tests. Operator credentials, runtime data, image binaries
and private development notes are excluded.

## Use the rescue stick

1. Submit one **public** OpenSSH key on the website. Keep the private key on your
   own computer. The website never needs it.
2. Download and extract the ZIP before the two-hour request expiry.
3. Write `DebRescueStick-amd64.img` to an entire USB device using an image writer.
   This replaces its contents. The image is 8 GiB + 8 MiB; use a nominal 16 GB or
   larger stick. The website includes Linux, macOS and Unix `dd` instructions.
4. Boot an AMD64 computer from the stick and connect wired Ethernet with DHCP.
   The local console displays addresses, SSH commands and public host-key
   fingerprints. Connect using `ssh root@debrstick.local`, or the displayed IP
   address, with your matching private key.

The `.local` name requires multicast DNS on the client and a network that allows
multicast. A second stick with the same name may receive an Avahi collision
suffix; the console displays the actual advertised name. Password SSH login is
disabled. The local rescue console provides root access to someone physically
at the machine. New host keys and machine identity are generated during boot.

The image contains Debian rescue tools including GNU ddrescue, TestDisk,
smartmontools, GParted, cryptsetup and rsync. The native website draft has English, German, French and Spanish editions.
Public visitor language/appearance behavior still needs acceptance after the
normal EORLS integration; editor preferences are not a substitute for that test.
The image is AMD64; writing it from an ARM Mac does not make it ARM-bootable.

## Architecture

An immutable, keyless Debian 13 base image has a separate 4 MiB FAT16 owner-key
partition. The boot service reads that partition only from the same disk as the
root filesystem. Missing or invalid owner keys prevent SSH startup.

The compressed system prefix is shared between requests. Personalization writes
and reads back the small key partition, compresses it and generates the ZIP64
ending with the combined CRC32. Clients receive a normal ZIP containing one
complete IMG, without a special extractor. Each request stores only its small
individual archive tail. Requests are serialized and bounded; expired individual
artifacts are removed without deleting the shared system prefix.

`server.py`, `store.py`, `keys.py`, `worker.py` and `fast.py` implement the service.
`image.py`, `fastbuild.py` and `image/` build the bootable image. `qualify.py` and
`mdns.py` qualify isolated firmware boots, SSH isolation, multicast discovery and
the console. `sources.py` preserves exact Debian corresponding sources, including
Built-Using dependencies. `update.py` promotes a qualified candidate with rollback.
`rollout.py` deploys frozen application releases. Other root tools include source
inventory, browser acceptance, archive extraction and historical migration tools.
The historical one-time migration commands are retained for completeness; they
are bound to their original receipts and are not general installation commands.

## Small local checks

Use Python 3.11 or later, Node.js 22 or later, OpenSSH client tools, Bash and GNU
coreutils. The standard gate uses only tiny synthetic fixtures:

Run all these lightweight checks with `sh check.sh`, or run them individually:

```sh
python3 -m unittest discover -s tests
node --check static/app.js
node --check static/ui.js
node --check preview.mjs
sh -n image/setup.sh
sh -n image/keys.sh
bash -n image/info.sh
```

Run the historical standalone frontend locally without image generation:

```sh
python3 server.py --state state --port 8080
```

Open `http://127.0.0.1:8080/debrescuestick/`. Image requests remain unavailable
without a qualified template and a live worker. Browser acceptance additionally
needs an isolated remote Chromium/CDP session and SSH tunnels; see `preview.py`.
No real media, VM or large image is needed for the local unit tests.

## Build and operate your own service

Use a dedicated Debian GNU/Linux build host with KVM, cgroup v2, systemd, enough
disk space to retain a 50 GiB reserve, libguestfs, QEMU, OVMF, mtools, dosfstools,
gdisk and the Apache modules used by `deploy/apache.conf`. These scripts perform
administrative operations and deliberately refuse arbitrary host or cgroup use.
Review the commands before running them. They manage only the project's own
service units and directories.

Copy `operator.env.example` to a private configuration file, set the exact remote
hostname and SSH destination, then source that file. No builder hostname is
selected by default. Configure your SSH alias with verified host keys. Frozen
remote jobs inherit the exact configured hostname through systemd; CPU and memory
guards remain enforced. Debian input versions and hashes are in `debian.lock.json`.

The image pipeline is:

```sh
python3 base.py submit
# Wait for and inspect this input job's successful receipt.
python3 image.py submit --mode build
# Wait for the normal image and use its ten-character job key below.
python3 fastbuild.py submit --template NORMAL_IMAGE_KEY
python3 qualify.py submit --template FAST_IMAGE_KEY
python3 sources.py submit --template FAST_IMAGE_KEY
```

Run these stages serially and inspect each tool's `status` command before
continuing. Never substitute a successful old job into a failed-build resume.
The worker additionally requires a protected root-owned
`/etc/debrescuestick/worker.json` containing the exact `hostname`. Deployment
helpers create or validate this marker. A first deployment uses `rollout.py`
with the successful image, QA and source job keys; inspect its command help.
`deploy/` contains the service and Apache configuration templates.

After a qualification unit has stopped, return its temporary disks and ephemeral
keys with `python3 qa_clean.py submit --qa QA_JOB_KEY`. This verifies the unit,
guest exit receipts and exact artifact ownership before removing individual
temporary files. Factory templates, production files and qualification proofs
are retained. Inspect the cleanup job's status as well.

The defaults use `/opt/debrescuestick`, `/var/lib/debrescuestick`,
`/etc/debrescuestick` and `/var/backups/debrescuestick`. Review origins, URL paths,
virtual hosts and service configuration for your installation. Run the public
HTTP service behind a correctly configured reverse proxy; it must replace the
client-IP header rather than trusting an incoming user-supplied value. The
worker is unprivileged and has no network access. Keep source archives available
for every image distributed, including superseded images.

## Qualification and limits

Firmware qualification uses isolated snapshots and virtual USB storage, owner-key
success, wrong-key/password rejection, cold host identities and clean shutdown.
The extended qualification covers BIOS, UEFI and enforced Secure Boot, plus a
multicast DNS peer in a separate network namespace inside the disposable guest.
Archive qualification verifies ZIP CRCs and independent extractors. Test tools
retain receipts; failed or incomplete checks must never be represented as passed.

Physical USB hardware and native Windows Explorer extraction are not yet
qualified. Individual firmware and network configurations may behave differently.
The Debian base and each third-party package retain their own support policies.

## Prepared Windows Shell ZIP acceptance

`explorer.ps1` is intended for our own disposable interactive Windows test guest
with Windows PowerShell 5.1 or later, started with `-STA`. It calls
`Shell.Application.CopyHere` rather than substituting `Expand-Archive` or a
third-party extractor. Microsoft documents that this call is asynchronous and
provides no completion notification. The checker waits for the exact IMG length,
exclusive readability and a full streaming SHA256 match. File existence or an
unchanged timestamp never counts as completion. See Microsoft's
[CopyHere documentation](https://learn.microsoft.com/en-us/windows/win32/shell/folder-copyhere).

Supply a completed ZIP, its SHA256 from the request and an independent SHA256
of the **personalized IMG inside that exact ZIP**, produced with libarchive or
7-Zip. The cold base template hash and another request's IMG hash are different.
For the current image the expected uncompressed size is exactly 8,598,323,200 bytes.
The tool creates its own new work directory, keeps the input ZIP intact, verifies
available space, and removes its own successful extraction after verification.
It writes a separate JSON receipt and returns zero only for verified data and
completed cleanup. Example for the automated guest operator:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -File .\explorer.ps1 -ZipPath C:\Test\image.zip -ZipSha256 $zipSha256 -ImageSha256 $personalImageSha256
```

The example uses a process-only execution policy for our own trusted checker
in a disposable test guest; it does not change the registry policy. See the
[PowerShell command-line reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).

Failure may leave a still-active Shell copy. The receipt marks this explicitly;
the tool preserves those files and never kills unrelated Explorer processes.
The outer guest job must impose a deadline and dispose of its own failed guest,
because a synchronous COM or native I/O call may itself block.

The native Windows/PowerShell 5.1 run is **still pending**. Testing the Shell ZIP
component also does not prove the entire Explorer ribbon/dialog workflow:
`explorerUiTested` remains false. Portable PowerShell 7.6.9 fixtures and parser
checks on Linux cover hashes, real file locking, progress despite identical
metadata, timeouts, ZIP metadata, refusal boundaries and cleanup. Those fixtures
explicitly report `nativeWindowsTested: false`. They use tiny synthetic files.
`python3 pscheck.py run` runs these additional guards on a separately managed
`browser.local` host, with a pinned vendor runtime, one CPU and 768 MiB limit.
Project scripts run from memory; the temporary runtime and fixtures are removed.
`ps.lock.json` pins the official runtime. No real image or Windows VM is needed
for those portable guards, and none is created on the development host.

## Automatic handoff to a Windows test guest

`handoff.py new` reuses the existing independent reference-extraction operator
on `browser.local`, waits for it to finish, returns its temporary resources,
and prepares a small guest payload. The operator first reserves that host using
its existing resource-management procedure. No VM is created by this command.
Alternatively, use a fresh completed reference with:

```sh
python3 handoff.py prepare --reference artifacts/extract-KEY/run.json
```

Preparation requires the exact pinned base, a successful stopped reference unit,
returned resources, the verified archive log and matching full-length libarchive
and 7-Zip IMG hashes. Live request metadata must still match. References from an
older schema, another request, an expired request or an unfinished test are refused.
The image and archive hashes are carried automatically; no manual hash entry is
needed in the guest.

The generated private folder contains `manifest.json`, both checker scripts and
`start.cmd`, plus a small `payload.zip` containing only those files. It contains a
short-lived download capability and must not be published. The launcher binds the
manifest hash; the manifest binds the script bytes, exact request URL, expiry,
archive length/hash and personalized IMG length/hash. **The large image ZIP never
passes through the development workstation.**

An existing VM controller places these small files on its normal test medium and
runs `start.cmd` in an interactive Windows session. `receive.ps1` downloads that
same ZIP directly in the guest, refuses redirects, validates length/hash and calls
the Shell checker with the bound references. It checks the resulting data and
script identities before accepting the report. `DRS_REPORT_PATH` may select an
existing parent directory's new report file; the default report goes to AppData
and stdout. Unknown or still-active artifacts are preserved on failure. No global
Explorer process is killed. The guest volume must fit two ZIP copies, the IMG
and a 1 GiB reserve; large files require a suitable local filesystem.

This follows the existing staged-test-medium and separate-report model rather
than introducing another Windows VM provisioner. The VM controller remains
responsible for a real Windows OS/image identity, its outer deadline, screenshot,
clean shutdown and resource return. Portable PowerShell fixtures cover the
receiver and its streaming download/abort logic. **A native guest handoff and the
complete Explorer UI workflow are still pending**, and portable results never
claim those tests have passed. Product images and production services are unchanged.

## License and sources

Original DebRescueStick software is copyright Richard Andresik and licensed under
**GPL-3.0-or-later**; see [COPYING](COPYING) and [NOTICE](NOTICE). This includes the
backend, web UI, builders, operator tools and tests. Debian and other third-party
software retain their individual licenses; their source requirements are not
replaced by this project's license. The public image source link contains exact
package sources for that image, rather than just links to a moving mirror.

`public.py export` produces a complete source-only export and a `SOURCES.json`
manifest with file sizes and SHA256 hashes. It excludes private configuration,
credentials, downloads, runtime state and private Git history. Historical
SystemRescueCD converter material remains a separate work under its original
authors' license and is not required to build this Debian-based project.
