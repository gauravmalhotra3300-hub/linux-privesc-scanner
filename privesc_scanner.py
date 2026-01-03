#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime

REPORT_PATH = "report_privesc.txt"

def run_cmd(cmd):
    try:
        out = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL,
            text=True
        )
        return out.strip()
    except subprocess.CalledProcessError:
        return ""

def write_report(line=""):
    with open(REPORT_PATH, "a") as f:
        f.write(line + "\n")

def header():
    open(REPORT_PATH, "w").close()
    write_report("# Linux Privilege Escalation Scan (Kali)")
    write_report(f"Date: {datetime.now()}")
    write_report("")

def system_info():
    write_report("## System Information")
    write_report(f"User: {run_cmd('whoami')}")
    write_report(f"ID: {run_cmd('id')}")
    write_report(f"Kernel: {run_cmd('uname -a')}")
    write_report("OS release:")
    write_report(run_cmd("cat /etc/os-release"))
    write_report("")

def suid_sgid_scan():
    write_report("## SUID / SGID Binaries")
    cmd = "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null"
    suid_list = run_cmd(cmd).splitlines()

    gtfobins = [
        "bash", "sh", "find", "perl", "python", "python3",
        "awk", "vi", "vim", "less", "more", "cp", "nano"
    ]

    if not suid_list:
        write_report("No SUID/SGID binaries found (or no permission to list).")
        write_report("")
        return

    for path in suid_list:
        basename = os.path.basename(path)
        if basename in gtfobins:
            write_report(f"[HIGH] GTFOBin SUID/SGID: {path}")
        else:
            write_report(f"[INFO] SUID/SGID: {path}")
    write_report("")

def world_writable():
    write_report("## World Writable Files/Directories")
    files_cmd = "find / -xdev -type f -perm -0002 2>/dev/null | head -n 200"
    dirs_cmd = "find / -xdev -type d -perm -0002 2>/dev/null | head -n 100"

    files = run_cmd(files_cmd).splitlines()
    dirs = run_cmd(dirs_cmd).splitlines()

    if not files and not dirs:
        write_report("No obvious world-writable files or directories in main filesystem.")
        write_report("")
        return

    for fpath in files:
        write_report(f"[MEDIUM] World-writable file: {fpath}")
    for dpath in dirs:
        write_report(f"[MEDIUM] World-writable dir: {dpath}")
    write_report("")

def passwd_shadow_perms():
    write_report("## Sensitive File Permissions")
    for f in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]:
        perms = run_cmd(f"ls -l {f}")
        if perms:
            write_report(f"{f}: {perms}")
        else:
            write_report(f"{f}: not accessible")
    write_report("")

def sudo_rights():
    write_report("## Sudo Rights")
    output = run_cmd("sudo -l")
    if output:
        write_report(output)
        if "NOPASSWD" in output:
            write_report("[HIGH] Sudo NOPASSWD entries found (potential privesc).")
    else:
        write_report("Cannot run 'sudo -l' or no sudo rights.")
    write_report("")

def cron_jobs():
    write_report("## Cron Jobs")
    locations = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron"
    ]

    for loc in locations:
        listing = run_cmd(f"ls -la {loc}")
        if listing:
            write_report(f"### {loc}")
            write_report(listing)
            write_report("")
    write_report("")

def services_check():
    write_report("## Services (systemd)")
    units = run_cmd("systemctl list-units --type=service --all --no-pager")
    if units:
        write_report(units)
    else:
        write_report("Could not list systemd services (maybe non-systemd OS or limited rights).")
    write_report("")

    write_report("### Potentially interesting service ExecStart lines")
    svc_names = run_cmd(
        "systemctl list-unit-files --type=service --no-pager | awk '{print $1}'"
    ).splitlines()

    checked_units = set()
    for svc in svc_names:
        if not svc.endswith(".service"):
            continue

        unit_file = run_cmd(
            f"systemctl show -p FragmentPath {svc} | cut -d'=' -f2"
        )
        if not unit_file or unit_file in checked_units:
            continue
        checked_units.add(unit_file)

        exec_line = run_cmd(f"grep -i '^ExecStart' {unit_file}")
        if exec_line:
            write_report(f"{svc}: {exec_line}")
    write_report("")

def kernel_cve_hint():
    write_report("## Kernel & CVE Hint")
    kernel = run_cmd("uname -r")
    write_report(f"Kernel version: {kernel}")
    write_report(
        "Action: Search for public exploits/CVEs for this kernel version "
        "on Exploit-DB, Google, or search engines."
    )
    write_report("")

def main():
    header()
    system_info()
    suid_sgid_scan()
    world_writable()
    passwd_shadow_perms()
    sudo_rights()
    cron_jobs()
    services_check()
    kernel_cve_hint()
    write_report("Scan complete.")

if __name__ == "__main__":
    main()
