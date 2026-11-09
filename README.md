# 🛡️ netconfig-audit

**Offline security audit for Cisco IOS and MikroTik RouterOS configs. It gives each config a score, explains every finding, and tells you the exact command that fixes it.**

![tests](https://github.com/anas352/netconfig-audit/actions/workflows/audit.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

It needs no device access: point it at saved config files (for example from
[netconfig-backup](https://github.com/anas352/netconfig-backup)) and get the results in the terminal, as HTML, as Markdown, or as JSON.

```
$ python netaudit.py samples/cisco-insecure.cfg

cisco-insecure.cfg  [cisco]  score 0/100 (F)
  HIGH   IOS-001  Telnet allowed on VTY lines
         ↳ telnet allowed on: line vty 0 4, line vty 5 15
         fix: line vty 0 15 → transport input ssh
  HIGH   IOS-002  'enable password' used instead of 'enable secret'
         ↳ enable password cisco123
         fix: no enable password / enable algorithm-type scrypt secret <pw>
  ...
```

## ✨ Features
- **30 checks**: 15 for Cisco IOS and 15 for MikroTik RouterOS (`python netaudit.py --list-rules`)
- **Score and grade** (A–F) per device, weighted by severity
- **Reports**: coloured terminal, a standalone **HTML** page ([example](docs/report-example.html)), **Markdown** (good for PRs) and **JSON**
- **CI gate**: `--fail-on high` returns exit code 1, so a pipeline can block risky changes
- **Understands both RouterOS export styles** (`/export` and `/export terse`)
- Single file, **zero dependencies**

## 🔍 What it checks

| Cisco IOS | MikroTik RouterOS |
|---|---|
| Telnet on VTY, missing VTY ACL | No `drop` rule on `chain=input` |
| `enable password`, `username … password` | Telnet / FTP / WWW / API services on |
| SNMP `public`/`private`, SNMP without ACL | Open DNS resolver (amplification) |
| `ip http server`, SSH v1 | Winbox open to any address |
| No `service password-encryption` | MAC-server / MAC-Winbox on all interfaces |
| No syslog / NTP / banner / AAA | Bandwidth-test server, SOCKS/proxy, UPnP |
| `exec-timeout 0 0`, CDP on | No NTP / remote logging / SSH strong crypto |

## 🚀 Usage
```bash
python netaudit.py router.cfg                       # one file
python netaudit.py backups/                         # whole folder (.cfg .conf .txt .rsc)
python netaudit.py backups/ -f html -o report.html  # HTML report
python netaudit.py backups/ --fail-on medium        # stricter CI gate
python netaudit.py backups/ --ignore IOS-015,MT-012 # skip rules you accept
```
For MikroTik, save the config with `/export terse file=router`, then download `router.rsc`.

## 🤖 Use it in CI
[`.github/workflows/audit.yml`](.github/workflows/audit.yml) runs the tests, posts the Markdown report on
the run's **Summary** page, and fails if a hardened config gains a high-severity finding.

## ➕ Adding a rule
```python
Rule("IOS-016", "cisco", "medium", "Source routing enabled", "no ip source-route",
     must_have(r"^no ip source-route")),
```

## 🧪 Tests
```bash
python -m unittest -v
```
`samples/` contains an insecure and a hardened config for each vendor. The tests check that the insecure ones
get the expected findings and that the hardened ones score 100.

---

## 🇸🇦 بالعربي
أداة **بتفحص أمان** ملفات إعدادات Cisco وMikroTik **من غير ما تتصل بالأجهزة**.
بتعطي كل جهاز علامة من 100، وبتشرح كل مشكلة (مثلاً Telnet مفتوح، أو SNMP public، أو ما في Firewall على الـ input)،
وبتعطيك **الأمر الجاهز للإصلاح**. التقرير بيطلع HTML أو Markdown أو JSON، وفيك تشغّلها بـ GitHub Actions.

MIT © 2026 Anas
