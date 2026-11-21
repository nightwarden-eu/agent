# NightWarden agent

Scripts of the [NightWarden](https://nightwarden.eu) inventory agent, published for independent verification.
This repository only mirrors released files; the agent is installed from your NightWarden server.

Agent 1.4.0. Every NightWarden release is a tag `vA.B.C` here (same version as the NightWarden server shows);
`SHA256SUMS` lists the SHA-256 of every script.

## Verify a script you downloaded from your NightWarden server

Linux (in the folder with the downloaded scripts):

```bash
curl -fsSLO https://raw.githubusercontent.com/nightwarden-eu/agent/vA.B.C/SHA256SUMS   # your server's version
sha256sum -c SHA256SUMS --ignore-missing     # use the same folder layout (linux/, windows/) or compare by hand
sudo nightwarden-agent update --sha256 <hash of linux/nightwarden-agent.sh from SHA256SUMS>
```

Windows (PowerShell):

```powershell
(Get-FileHash .\nightwarden-agent.ps1 -Algorithm SHA256).Hash   # compare with windows/nightwarden-agent.ps1 in SHA256SUMS
```

The checksum proves the script is the released one even if your server or the connection was tampered with.
It does not protect against a compromised source repository; signed scripts are planned.
