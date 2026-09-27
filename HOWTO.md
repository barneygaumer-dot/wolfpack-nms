# WolfPack NMS — Comprehensive HOWTO

This guide covers fresh installation, initial configuration, discovery, polling, topology collection, ARP evidence, synthetic monitoring, email alerts, validation, upgrades, backup/recovery, troubleshooting, and Git preparation for WolfPack NMS 1.3.11.

## 1. Deployment assumptions

The current build is designed around a Linux NMS host and is primarily developed on Ubuntu 24.04. The packaged systemd service runs as root because low-level polling/collection functions and the current operational model assume host-level access. Treat the NMS host as management infrastructure.

Default application location:

```text
/opt/wolfpack/nms
```

Default database:

```text
/opt/wolfpack/nms/wolfpack.db
```

Default web listener:

```text
0.0.0.0:8088
```

Default systemd unit:

```text
wolfpack-nms.service
```

## 2. Fresh installation

Extract the release and run the installer as root:

```bash
unzip WolfPack-NMS-1.3.11.zip
cd WolfPack-NMS-1.3.11
sudo ./install.sh
```

The installer:

1. Installs required OS packages.
2. Creates `/opt/wolfpack/nms`.
3. Copies application files.
4. Creates `/opt/wolfpack/nms/.venv`.
5. Installs Python dependencies from `requirements.txt`.
6. Creates `/etc/systemd/system/wolfpack-nms.service`.
7. Enables and starts the service.

Validate it:

```bash
systemctl status wolfpack-nms --no-pager
curl -fsS http://127.0.0.1:8088/api/health
```

Expected health response includes:

```json
{"status":"healthy","version":"1.3.11"}
```

Determine the host address if needed:

```bash
hostname -I
```

Then browse to:

```text
http://SERVER-IP:8088
```

## 3. Service operations

Check status:

```bash
sudo systemctl status wolfpack-nms --no-pager
```

Restart:

```bash
sudo systemctl restart wolfpack-nms
```

Stop/start:

```bash
sudo systemctl stop wolfpack-nms
sudo systemctl start wolfpack-nms
```

Follow logs:

```bash
sudo journalctl -u wolfpack-nms -f
```

Recent logs:

```bash
sudo journalctl -u wolfpack-nms -n 200 --no-pager
```

Confirm the listener:

```bash
ss -lntp | grep ':8088'
```

## 4. Initial Admin / Setup configuration

Open **Admin / Setup**.

Configure the site and polling values appropriate for the deployment. The application persists settings in SQLite.

Important: changing a setting in the UI does not make the application Internet-safe. WolfPack NMS should remain on a trusted management network unless additional authentication, authorization, TLS termination, and hardening are deployed externally.

## 5. Discovering devices

Use the Dashboard discovery form and enter a CIDR such as:

```text
10.23.10.0/24
```

The current discovery engine has a safety limit of `/22` or smaller per request. It probes hosts with ICMP and adds responding devices to inventory.

Discovery is intentionally not the same thing as full device characterization. After discovery, open the device object and configure the polling and metadata appropriate to that endpoint.

## 6. Device configuration

Open **Devices**, select a node, and configure the relevant fields.

### Identity and classification

Useful fields include:

- hostname
- display name
- description
- platform class: Windows, Linux/Unix, IoT, or Network Device
- location
- vendor
- model
- notes

### Poll method

Choose the method that best represents useful reachability for the device:

**ICMP** — basic IP reachability.

**TCP** — successful connection to a configured TCP port.

**ARP** — Layer-2 presence on the configured local interface.

**UDP** is present in the model but the current engine does not declare generic UDP success without protocol-specific response criteria.

### ARP fallback

For a same-segment device that may ignore ICMP, enable ARP fallback and select the correct NMS interface.

Example logic:

```text
ICMP FAIL + ARP PASS -> device remains UP
ICMP FAIL + ARP FAIL -> device is DOWN
```

Do not interpret ARP fallback as application/service health. It proves local Layer-2 presence only.

### Alert group

Select the configured alert group if this device should generate email state-transition alerts. Leave it as **None** to suppress email alerts for the device.

## 7. Polling and evidence

A poll writes evidence and updates current device state.

Primary poll evidence is recorded with check types such as:

```text
POLL-ICMP
POLL-TCP
POLL-ARP
```

The evidence row contains PASS/FAIL, optional timing data, and detail describing the primary/fallback result.

The dashboard's 24-hour health visualization is built from recorded `POLL-%` evidence. It uses 24 fixed clock-hour positions. Hours without evidence remain empty rather than being invented or interpolated.

## 8. Stateful email alerting

### Alert behavior

WolfPack intentionally alerts on **transitions**, not persistent conditions:

```text
UP -> DOWN     one DOWN notification
DOWN -> DOWN   no notification
DOWN -> UP     one CLEARED notification
UP -> UP       no notification
```

An initial `UNKNOWN -> DOWN` does not send a DOWN alert. This avoids generating startup noise before WolfPack has established a prior UP state.

### Configure SMTP

Open **Admin / Setup -> Email Alerting — v1** and configure:

- alert group name
- alert group enabled/disabled
- recipients
- SMTP host
- SMTP port
- SMTP username
- SMTP password
- STARTTLS
- From name
- From address

Recipients can be separated by commas or semicolons.

Your SMTP provider may require the From address/domain to be verified or may issue a fixed sender address. Follow the provider's policy.

### Test SMTP

Use **Send Test Email** in Admin / Setup.

A successful message has the subject:

```text
WolfPack NMS — Test Email
```

and confirms that NMS can authenticate and relay mail to the configured recipient.

### Perform a real state-transition test

Use an expendable lab device, not production infrastructure.

1. Confirm the device is currently `UP` in WolfPack.
2. Assign the alert group and save the device.
3. Make the test device unavailable.
4. Run/wait for a poll that changes the device from `UP` to `DOWN`.
5. Confirm exactly one DOWN email arrives.
6. Poll the still-down device again and confirm **no additional DOWN email** arrives.
7. Restore the device.
8. Poll again and confirm exactly one CLEARED email arrives.
9. Inspect Recent Node Evidence for `ALERT-EMAIL-DOWN` and `ALERT-EMAIL-CLEAR` delivery evidence.

### Important delivery limitation

The current implementation attempts email at the time of the state transition. It does **not yet implement a persistent notification retry queue**. If SMTP/Internet connectivity is unavailable at the transition, the failed send is preserved as evidence, but the message is not automatically replayed later.

This matters especially when the monitored firewall/core path is also the path NMS uses to reach the SMTP relay.

## 9. Synthetic checks

WolfPack supports synthetic checks for:

- ICMP
- DNS
- TCP
- HTTP
- HTTPS

Synthetics are stored separately from device polling and record their latest result plus evidence.

Use TCP/HTTP/HTTPS synthetics when service availability matters more than simple host reachability.

## 10. SSH authentication and collection

Device objects include SSH configuration for supported network-device collection.

Configure:

- SSH enabled
- username
- password
- port
- management role

Use **Test Authentication** before collection. Authentication results are recorded as evidence.

Use collection only against systems you are authorized to manage. The current implementation stores the configured SSH password in the SQLite database; protect the host and database accordingly.

## 11. Topology and adjacency

The Network Map combines discovered/configured devices with topology evidence and operator-defined relationships.

A device can be assigned:

- management role
- adjacent device
- adjacent interface
- local interface

Interface inventories collected from devices populate interface choices where available.

Operator-configured topology is evidence of operator intent/configuration; it should not be confused with an automatically proven physical connection.

## 12. ARP evidence

The **ARP Evidence** view records IP/MAC observations with observer context.

That observer context matters. A MAC address is a Layer-2 relationship and normally has meaning on the observer's local segment. Across routed networks, routers resolve their next hop; the router directly connected to the endpoint's segment is the useful observer for the endpoint's ARP relationship.

Treat old IP/MAC relationships as historical evidence, not timeless identity. DHCP, replacement hardware, virtual interfaces, and topology changes can legitimately alter relationships.

## 13. Database inspection

The production database is SQLite. Stop or back up appropriately before performing invasive manual maintenance.

Basic table listing:

```bash
sudo sqlite3 /opt/wolfpack/nms/wolfpack.db '.tables'
```

Recent evidence:

```bash
sudo sqlite3 -header -column /opt/wolfpack/nms/wolfpack.db \
  "SELECT id,ts,device_id,check_type,status,value,detail FROM evidence ORDER BY id DESC LIMIT 30;"
```

Active/open alerts:

```bash
sudo sqlite3 -header -column /opt/wolfpack/nms/wolfpack.db \
  "SELECT * FROM active_alerts WHERE status='OPEN' ORDER BY id DESC;"
```

Do not publish the operational database. It may contain network inventory and credentials.

## 14. Backup

At minimum, preserve the application database and current application tree.

For a clean manual application backup:

```bash
sudo systemctl stop wolfpack-nms
sudo cp -a /opt/wolfpack/nms /opt/wolfpack/nms-manual-backup-$(date +%Y%m%d-%H%M%S)
sudo systemctl start wolfpack-nms
```

For SQLite-only backup while the application is running, prefer SQLite's backup mechanism rather than copying a busy WAL database blindly:

```bash
sudo sqlite3 /opt/wolfpack/nms/wolfpack.db \
  ".backup '/tmp/wolfpack-nms-backup.db'"
```

Protect backups as sensitive operational data.

## 15. Upgrade from ZIP

### Web updater

Open **Admin / Setup -> Update From ZIP**, choose the release ZIP, and launch the update.

The web route starts the lifecycle updater in a transient systemd unit so the updater survives the NMS service restart.

After 10–20 seconds, validate:

```bash
curl -fsS http://127.0.0.1:8088/api/health
```

If the UI gives you the transient unit name, inspect it with:

```bash
sudo journalctl -u UNIT-NAME --no-pager
```

### CLI updater

```bash
sudo /opt/wolfpack/nms/update.sh /path/to/release.zip
```

The packaged updater:

1. Copies the current application into `/opt/wolfpack/nms-backups`.
2. Extracts the release.
3. Stops NMS.
4. Replaces application code.
5. Refreshes Python requirements.
6. Starts NMS.
7. Checks `/api/health`.
8. Rolls back if the health check fails.

## 16. Troubleshooting

### UI does not load

```bash
systemctl status wolfpack-nms --no-pager
sudo journalctl -u wolfpack-nms -n 200 --no-pager
ss -lntp | grep ':8088'
curl -v http://127.0.0.1:8088/api/health
```

### Poll fails unexpectedly

Check the configured poll method and test the equivalent operation manually from the NMS host.

ICMP:

```bash
ping -c 3 DEVICE-IP
```

TCP:

```bash
nc -vz DEVICE-IP PORT
```

ARP:

```bash
sudo arping -I INTERFACE -c 3 DEVICE-IP
```

Remember that ARP does not normally cross a router.

### Email test fails

Verify:

1. SMTP hostname and port.
2. STARTTLS requirement.
3. username/password.
4. provider-issued or verified From address.
5. recipient syntax.
6. DNS resolution from the NMS host.
7. outbound TCP reachability to the relay.

Useful checks:

```bash
getent hosts SMTP-HOST
nc -vz SMTP-HOST SMTP-PORT
sudo journalctl -u wolfpack-nms -n 100 --no-pager
```

Never paste SMTP credentials into a public issue or commit them to Git.

### Device remains UP after ICMP failure

If ARP fallback is enabled, inspect Recent Node Evidence. An entry such as:

```text
ICMP FAIL; ARP/INTERFACE PASS (L2 fallback)
```

means the primary check failed but local Layer-2 presence was confirmed.

### Health graph has empty hours

That is expected when there is no polling evidence for those clock-hour buckets. WolfPack does not manufacture historical availability data.

## 17. Git/GitHub preparation

Before the first commit:

```bash
git init
git status --short
```

Review ignored files:

```bash
git status --ignored --short
```

Search the working tree for obvious secrets before staging. At minimum inspect for SMTP credentials, SSH passwords, SNMP community strings, API keys, tokens, private keys, databases, and environment files.

Then stage deliberately:

```bash
git add README.md HOWTO.md SECURITY.md CONTRIBUTING.md .gitignore
git add install.sh update.sh requirements.txt run.py wolfpack_nms/
git status
```

Do **not** use `git add -A` until you have reviewed the tree.

After review:

```bash
git commit -m "Prepare WolfPack NMS 1.3.11 for public repository"
```

Before making a repository public, enable GitHub secret scanning/push protection where available and review the complete commit history for secrets — deleting a secret from the latest file does not remove it from earlier commits.

## 18. Known limitations / roadmap candidates

Current 1.3.11 limitations worth tracking:

- one configurable alert group
- email transport only
- no persistent notification retry/queue
- no authentication/authorization layer in the application UI
- no integrated TLS termination
- credentials stored locally in SQLite
- generic UDP polling intentionally does not claim success without protocol-specific criteria
- discovery limited to `/22` or smaller per request
- topology quality depends on available evidence and operator configuration

Natural future work includes multiple alert groups, queued/retried notifications, SMS/webhook transports, credential vault integration, stronger RBAC/authentication, and additional topology/evidence collectors.

## 19. Operational philosophy

WolfPack NMS is designed around three ideas:

**State is useful; evidence is better.** Preserve what was observed and how it was observed.

**Alert on change, not repetition.** Operators need to know that something changed, not receive hundreds of reminders that the same condition still exists.

**Observer context matters.** Especially at Layer 2, record who observed a relationship, where, and when.
