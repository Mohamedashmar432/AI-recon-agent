#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import shutil
import re
from datetime import datetime, timedelta
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Colors
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Style.RESET_ALL

# Global variables
TARGET = ""
OUTPUT_DIR = ""
ERROR_LOG = ""
START_TIME = time.time()
REPORT_LINES = []

def log(msg, color=RESET):
    print(f"{color}[*] {msg}{RESET}")

def error(msg):
    with open(ERROR_LOG, "a") as f:
        f.write(f"[ERROR] {datetime.now()} - {msg}\n")
    print(f"{RED}[❌] {msg}{RESET}")

def success(msg):
    print(f"{GREEN}[✅] {msg}{RESET}")

def warn(msg):
    print(f"{YELLOW}[⚠️] {msg}{RESET}")

def expand_path(path):
    """Expand ~ and resolve relative paths"""
    return os.path.abspath(os.path.expanduser(path.strip()))

def get_output_directory(target):
    log("📁 Where would you like to save the output?", CYAN)
    log(f"💡 Default: current directory ('./{target}/')", YELLOW)
    choice = input(f"[→] Enter path (or press Enter for default): ").strip()

    if not choice:
        return target  # Save in current dir as 'target.com/'

    try:
        base_path = expand_path(choice)
        final_path = os.path.join(base_path, target)
        os.makedirs(final_path, exist_ok=True)
        success(f"Output directory set: {final_path}")
        return final_path
    except Exception as e:
        warn(f"Invalid path: {choice} | Error: {e}")
        warn("Falling back to current directory.")
        return target

def run_command(cmd, output_file=None, shell=True, timeout_duration=600):
    start = time.time()
    log(f"🚀 Running: {cmd}", BLUE)

    try:
        if output_file:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            with open(output_file, "w") as f:
                result = subprocess.run(
                    cmd, shell=shell, stdout=f, stderr=subprocess.PIPE, timeout=timeout_duration
                )
            if result.returncode != 0:
                stderr = result.stderr.decode().strip()
                error(f"Command failed: {os.path.basename(cmd.split()[0])} | {stderr[:200]}")
                return False
        else:
            result = subprocess.run(
                cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_duration
            )
            if result.returncode != 0:
                stderr = result.stderr.decode().strip()
                error(f"Command failed: {os.path.basename(cmd.split()[0])} | {stderr[:200]}")
                return None
            return result.stdout.decode()

        duration = time.time() - start
        success(f"✔️ Done in {duration:.1f}s → {os.path.basename(output_file)}")
        return True

    except subprocess.TimeoutExpired:
        error(f"⏰ Timeout ({timeout_duration}s): {cmd.split()[0]}")
        return False
    except Exception as e:
        error(f"💥 Error: {str(e)[:200]}")
        return False

def install_tool(tool, install_cmd):
    if shutil.which(tool):
        success(f"{tool} is installed.")
        return True
    warn(f"{tool} not found. Installing via: {install_cmd}")
    return run_command(install_cmd)

def setup_environment():
    global OUTPUT_DIR, ERROR_LOG
    OUTPUT_DIR = get_output_directory(TARGET)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ERROR_LOG = os.path.join(OUTPUT_DIR, "errors.log")
    open(ERROR_LOG, 'w').close()

    REPORT_LINES.append(f"🔍 Recon Report for: {TARGET}")
    REPORT_LINES.append(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    REPORT_LINES.append(f"💾 Output Directory: {OUTPUT_DIR}")
    REPORT_LINES.append("=" * 60)

def estimate_total_time():
    estimates = {
        "manual": 60,
        "google_dorks": 5,
        "metadata": 10,
        "subfinder": 60,
        "crtsh": 30,
        "httpx": 60,
        "naabu": 120,
        "gau": 60,
        "uro": 20,
        "secretfinder": 120,
        "nuclei": 300
    }
    total_sec = sum(estimates.values())
    finish_time = datetime.now() + timedelta(seconds=total_sec)
    log(f"📊 Estimated total runtime: ~{total_sec//60} min", CYAN)
    log(f"🎯 Estimated finish: {finish_time.strftime('%H:%M')}", CYAN)
    return total_sec

def step_1_manual_recon():
    log("STEP 1: Manual Recon – Understand the target", YELLOW)
    log(f"🌐 Open: https://{TARGET}", YELLOW)
    input(f"{YELLOW}[→] Press ENTER after reviewing...{RESET}")
    success("Manual recon complete.")

def step_2_google_dorks():
    log("STEP 2: Google Dorks", YELLOW)
    dorks = [
        f'site:{TARGET}',
        f'inurl:admin site:{TARGET}',
        f'intitle:"login" site:{TARGET}',
        f'filetype:pdf site:{TARGET}',
        f'intext:"@{TARGET}"',
        f'site:*.herokuapp.com {TARGET}',
        f'site:github.com {TARGET}',
        f'site:gitlab.com {TARGET}',
    ]
    output_file = f"{OUTPUT_DIR}/google_dorks.txt"
    with open(output_file, "w") as f:
        for dork in dorks:
            f.write(f"https://google.com/search?q={dork.replace(' ', '+')}\n")
    success(f"Google dorks saved → {output_file}")
    REPORT_LINES.append(f"Google Dorks → {output_file}")

def step_3_metadata():
    log("STEP 3: Checking metadata endpoints", YELLOW)
    urls = [
        f"https://{TARGET}/robots.txt",
        f"https://{TARGET}/sitemap.xml",
        f"https://{TARGET}/security.txt",
        f"https://{TARGET}/.well-known/security.txt",
        f"https://{TARGET}/.well-known/ai-plugin.json",
        f"https://{TARGET}/.well-known/assetlinks.json",
    ]
    output_file = f"{OUTPUT_DIR}/metadata.txt"
    with open(output_file, "w") as f:
        for url in urls:
            try:
                r = subprocess.run(f"curl -s -I -L --max-time 10 {url}", shell=True, capture_output=True)
                f.write(f"{url}\n{r.stdout.decode()}\n{'-'*40}\n")
            except:
                f.write(f"{url} → Failed\n")
    success(f"Metadata saved → {output_file}")
    REPORT_LINES.append(f"Metadata → {output_file}")

def step_4_subfinder():
    log("STEP 4: Subdomain Enumeration", YELLOW)
    install_tool("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    output_file = f"{OUTPUT_DIR}/subdomains_subfinder.txt"
    cmd = f"subfinder -d {TARGET} -all -nW -o {output_file}"
    if run_command(cmd):
        REPORT_LINES.append(f"subfinder → {output_file}")

def step_5_crt_sh():
    log("STEP 5: Extracting subdomains from crt.sh", YELLOW)
    output_file = f"{OUTPUT_DIR}/subdomains_crtsh.txt"
    cmd = f"curl -s https://crt.sh/?q=%25.{TARGET}&output=json | jq -r '.[].name_value' | tr ';' '\\n' | sed 's/\\*\\.//g' | sort -u | grep -i '{re.escape(TARGET)}$' | anew {output_file}"
    if run_command(cmd):
        REPORT_LINES.append(f"crt.sh → {output_file}")

def step_6_merge_and_httpx():
    log("STEP 6: Probing alive subdomains with httpx", YELLOW)
    install_tool("httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    all_sub_file = f"{OUTPUT_DIR}/subdomains_all.txt"
    alive_file = f"{OUTPUT_DIR}/subdomains_alive.txt"

    # Merge and deduplicate
    os.system(f"cat {OUTPUT_DIR}/subdomains_*.txt 2>/dev/null | anew {all_sub_file}")
    if not os.path.exists(all_sub_file) or os.path.getsize(all_sub_file) == 0:
        warn("No subdomains found. Skipping httpx.")
        return

    cmd = f"cat {all_sub_file} | httpx -ports 80,443,8080 -threads 200 -status-code -title -tech-detect -o {alive_file}"
    if run_command(cmd):
        REPORT_LINES.append(f"httpx → {alive_file}")

def step_7_naabu():
    log("STEP 7: Fast port scan with naabu", YELLOW)
    install_tool("naabu", "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    input_file = f"{OUTPUT_DIR}/subdomains_alive.txt"
    if not os.path.exists(input_file):
        warn("No alive subdomains. Skipping naabu.")
        return

    output_file = f"{OUTPUT_DIR}/naabu_ports.txt"
    cmd = f"naabu -list {input_file} -top-ports 1000 -c 50 -silent | anew {output_file}"
    if run_command(cmd):
        REPORT_LINES.append(f"naabu → {output_file}")

def step_8_gau():
    log("STEP 8: Fetching URLs with gau", YELLOW)
    install_tool("gau", "go install github.com/lc/gau/v2/cmd/gau@latest")
    input_file = f"{OUTPUT_DIR}/subdomains_alive.txt"
    if not os.path.exists(input_file):
        warn("No alive subdomains. Skipping gau.")
        return

    output_file = f"{OUTPUT_DIR}/urls_gau.txt"
    cmd = f"cat {input_file} | gau --o {output_file}"
    if run_command(cmd):
        REPORT_LINES.append(f"gau → {output_file}")

def step_9_uro():
    log("STEP 9: Filtering URLs with uro", YELLOW)
    install_tool("uro", "go install github.com/kh4sh3i/uro@latest")
    input_file = f"{OUTPUT_DIR}/urls_gau.txt"
    if not os.path.exists(input_file):
        warn("No URLs from gau. Skipping uro.")
        return

    filtered = f"{OUTPUT_DIR}/urls_filtered.txt"
    js_out = f"{OUTPUT_DIR}/js_files.txt"

    run_command(f"cat {input_file} | uro -o {filtered}")
    run_command(f"cat {filtered} | grep -i '.js' | uro -o {js_out}")

    success(f"Filtered URLs → {filtered}")
    success(f"JS Files → {js_out}")
    REPORT_LINES.append(f"uro (params) → {filtered}")
    REPORT_LINES.append(f"uro (js) → {js_out}")

def step_10_secretfinder():
    log("STEP 10: Hunting secrets in JS files", YELLOW)
    js_file = f"{OUTPUT_DIR}/js_files.txt"
    if not os.path.exists(js_file) or os.path.getsize(js_file) == 0:
        warn("No JS files found. Skipping SecretFinder.")
        return

    output_file = f"{OUTPUT_DIR}/js_secrets.txt"
    cmd = (
        f"cat {js_file} | while read url; do "
        f"echo '--- $url ---'; "
        f"python3 /home/ashmar/playgorund/secretfinder/SecretFinder.py -i \"$url\" -o cli; "
        f"done > {output_file}"
    )
    if run_command(cmd):
        REPORT_LINES.append(f"SecretFinder → {output_file}")

def step_11_nuclei():
    log("STEP 11: Scanning with Nuclei", YELLOW)
    install_tool("nuclei", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    input_file = f"{OUTPUT_DIR}/urls_filtered.txt"
    if not os.path.exists(input_file):
        warn("No input URLs. Skipping nuclei.")
        return

    output_file = f"{OUTPUT_DIR}/nuclei_findings.txt"
    templates = "/home/ashmar/playgorund/nuclei-templates/"
    cmd = (
        f"nuclei -list {input_file} -t {templates} -es info -rl 100 -c 50 "
        f"-stats -o {output_file}"
    )
    if run_command(cmd):
        count = len(open(output_file).readlines()) if os.path.exists(output_file) else 0
        severity = "HIGH" if count > 0 else "low"
        success(f"Nuclei → {output_file} [{count} findings]")
        REPORT_LINES.append(f"nuclei ({severity}) → {output_file}")

def generate_report():
    log("📄 Generating final report...", GREEN)
    total_time = time.time() - START_TIME
    report_file = f"{OUTPUT_DIR}/report_{TARGET}.txt"
    with open(report_file, "w") as f:
        f.write("\n".join(REPORT_LINES))
        f.write(f"\n\n⏱️  Total Time: {total_time:.1f}s (~{int(total_time//60)} min)")
        f.write(f"\n📂 All results in: {OUTPUT_DIR}/\n")
    success(f"✅ Report saved: {report_file}")

def main():
    global TARGET
    if len(sys.argv) != 2:
        print(f"{RED}Usage: python3 {sys.argv[0]} <target-domain>{RESET}")
        sys.exit(1)

    TARGET = sys.argv[1].strip().lower()
    if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.[a-z]{2,}$', TARGET):
        error("Invalid domain format.")
        sys.exit(1)

    # Banner
    print(f"""
{BLUE}╔════════════════════════════════════════╗
║{CYAN}    🔥 FINAL RECON ENGINE v4.0 🔥        {BLUE}║
║{YELLOW}     User Path • Silent • Pro           {BLUE}║
╚════════════════════════════════════════╝{RESET}
Target: {CYAN}{TARGET}{RESET}
    """)

    setup_environment()
    estimate_total_time()

    steps = [
        step_1_manual_recon,
        step_2_google_dorks,
        step_3_metadata,
        step_4_subfinder,
        step_5_crt_sh,
        step_6_merge_and_httpx,
        step_7_naabu,
        step_8_gau,
        step_9_uro,
        step_10_secretfinder,
        step_11_nuclei
    ]

    try:
        for i, step in enumerate(steps, 1):
            log(f"🔄 [{i:2d}/{len(steps)}]", CYAN)
            start = time.time()
            step()
            duration = time.time() - start
            log(f"✅ Step {i} completed in {duration:.1f}s", GREEN)
    except KeyboardInterrupt:
        error("Recon interrupted by user.")
    except Exception as e:
        error(f"Unexpected error: {e}")
    finally:
        generate_report()
        log(f"🎯 Recon complete for {TARGET}", GREEN)

if __name__ == "__main__":
    main()