# Security Policy

## Project status

WolfPack NMS 1.3.11 is intended for trusted management networks, homelabs, and controlled NOC/lab environments. It is **not currently designed to be exposed directly to the public Internet**.

## Important current security characteristics

- The web application does not currently provide its own user authentication or authorization layer.
- The default service listens on `0.0.0.0:8088`.
- The packaged systemd service currently runs as root.
- SSH passwords, SNMP community strings, and SMTP credentials configured through the UI are stored in the local SQLite database.
- The application uses HTTP unless an external reverse proxy/TLS layer is added.
- Network discovery, polling, SSH collection, and topology functions should only be used on networks and devices you are authorized to monitor/manage.

Protect the NMS host, restrict TCP/8088 with host/network controls, and treat `wolfpack.db` and backups as sensitive.

## Repository hygiene

Never commit:

- `wolfpack.db` or other operational databases
- SQLite WAL/SHM files
- `.env` files
- SMTP usernames/passwords
- SSH credentials
- SNMP community strings
- API keys/tokens
- private keys/certificates containing private material
- operational evidence/log exports containing sensitive network data

The repository includes `.gitignore` rules for common artifacts, but contributors must still review `git status` and commits before pushing.

## Reporting a vulnerability

Do not open a public issue containing credentials, exploit details against a live deployment, or sensitive network data. Contact the repository owner privately and include the affected version, component, reproduction conditions, and impact. A dedicated private reporting address/process can be added when the public repository is created.
