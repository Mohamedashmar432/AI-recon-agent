#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import shutil
from datetime import datetime
import re
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Global variables
TARGET = ""
OUTPUT_DIR = ""
ERROR_LOG = ""
START_TIME = time.time()
REPORT_LINES = []

# Colors
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Style.RESET_ALL

def banner():
    print(f"""
{BLUE}╔══════════════════════════════════════════════════╗
║{CYAN}     🔥 AUTOMATED BUG BOUNTY RECON ENGINE 🔥      {BLUE}║
║{YELLOW}           By: Offensive Cyber Researcher          {BLUE}║
╚══════════════════════════════════════════════════╝{RESET}
    """)
    time.sleep(1)

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

def run_command(cmd, output_file=None, shell=True, timeout_duration=3600):
    start = time.time()
    try:
        log(f"Running: {cmd}", BLUE)
        if output_file:
            with open(output_file, "w") as f:
                result = subprocess.run(
                    cmd, shell=shell, stdout=f, stderr=subprocess.PIPE, timeout=timeout_duration
                )
            if result.returncode != 0:
                error(f"Command failed: {cmd} | Error: {result.stderr.decode()}")
                return False
        else:
            result = subprocess.run(
                cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_duration
            )
            if result.returncode != 0:
                error(f"Command failed: {cmd} | Error: {result.stderr.decode()}")
                return None
            return result.stdout.decode()

        duration = time.time() - start
        success(f"Completed in {duration:.2f}s → Output: {output_file}")
        return True

    except subprocess.TimeoutExpired:
        error(f"Command timed out: {cmd}")
        return False
    except Exception as e:
        error(f"Exception running command: {e}")
        return False

def install_tool(tool, install_cmd):
    if shutil.which(tool):
        success(f"{tool} is already installed.")
        return True
    warn(f"{tool} not found. Installing...")
    return run_command(install_cmd)

def setup_environment():
    log("Setting up environment...", CYAN)
    global OUTPUT_DIR, ERROR_LOG
    OUTPUT_DIR = f"output/{TARGET}"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ERROR_LOG = f"{OUTPUT_DIR}/errors.log"
    open(ERROR_LOG, 'w').close()  # Clear error log
    REPORT_LINES.append(f"Recon Report for: {TARGET}")
    REPORT_LINES.append(f"Started at: {datetime.now()}")
    REPORT_LINES.append("="*60)

def step_1_manual_recon():
    log("STEP 1: Manual Recon - Visit target and understand purpose", YELLOW)
    log(f"Open in browser: https://{TARGET}", YELLOW)
    input(f"{YELLOW}[→] Press ENTER after you've reviewed the site manually...{RESET}")
    success("Manual recon completed.")

def step_2_google_dorks():
    log("STEP 2: Running Google Dorks", YELLOW)
    dorks = [
        f'site:{TARGET}',
        f'cache:{TARGET}',
        f'inurl:{TARGET}',
        f'allinurl:{TARGET}',
        f'intitle:{TARGET}',
        f'intext:{TARGET}',
        f'filetype:xls inurl:"email" site:{TARGET}',
        f'inurl:admin site:{TARGET}',
        f'intitle:"2022" ("Income statement" | "Profit & Loss Statement" | "P&L") filetype:pdf site:{TARGET}',
        f'inurl:github.com filename:database intext:{TARGET}',
        f'inurl:gitlab.com secret.yaml | credentials.xml intext:site:{TARGET}',
        f'site:drive.google.com {TARGET}',
        f'site:{TARGET} ext:php'
    ]
    output_file = f"{OUTPUT_DIR}/google_dorks.txt"
    with open(output_file, "w") as f:
        for dork in dorks:
            f.write(f"https://google.com/search?q={dork.replace(' ', '+')}\n")
    success(f"Google dorks saved to {output_file}")

def step_3_metadata():
    log("STEP 3: Checking metadata endpoints", YELLOW)
    endpoints = [
        f"https://{TARGET}/robots.txt",
        f"https://{TARGET}/sitemap.xml",
        f"https://{TARGET}/humans.txt",
        f"https://{TARGET}/security.txt",
        f"https://{TARGET}/.well-known/security.txt",
        f"https://{TARGET}/.well-known/assetlinks.json",
        f"https://{TARGET}/.well-known/ai-plugin.json"
    ]
    output_file = f"{OUTPUT_DIR}/metadata_responses.txt"
    with open(output_file, "w") as f:
        for url in endpoints:
            try:
                result = subprocess.run(
                    f"curl -s -I -L --max-time 10 {url}", shell=True, capture_output=True
                )
                f.write(f"{url}\n{result.stdout.decode()}\n{'-'*50}\n")
            except:
                f.write(f"{url} → Failed\n")
    success(f"Metadata checks saved to {output_file}")

def step_4_subfinder():
    log("STEP 4: Running subfinder", YELLOW)
    install_tool("subfinder", "sudo apt install -y subfinder || go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    output_file = f"{OUTPUT_DIR}/subdomains_raw.txt"
    cmd = f"subfinder -d {TARGET} -all -recursive -o {output_file}"
    if run_command(cmd, None):  # No file redirect (subfinder handles it)
        success(f"Subdomains saved to {output_file}")
        REPORT_LINES.append(f"subfinder → {output_file}")

def step_5_crt_sh():
    log("STEP 5: Probing crt.sh for subdomains", YELLOW)
    output_file = f"{OUTPUT_DIR}/subdomains_crtsh.txt"
    cmd = (f"curl -s https://crt.sh/?q=%25.{TARGET}&output=json | "
           f"jq -r '.[].name_value' | sort -u | grep -Po '([a-zA-Z0-9._\\-]+\\.)+{re.escape(TARGET)}$' | anew {output_file}")
    if run_command(cmd):
        success(f"crt.sh results saved to {output_file}")
        REPORT_LINES.append(f"crt.sh → {output_file}")

def step_6_httpx():
    log("STEP 6: Checking alive subdomains with httpx", YELLOW)
    install_tool("httpx", "sudo apt install -y httpx-toolkit || go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    input_file = f"{OUTPUT_DIR}/subdomains_all.txt"
    # Merge all subdomain sources
    os.system(f"cat {OUTPUT_DIR}/subdomains_*.txt 2>/dev/null | anew {input_file}")
    if not os.path.getsize(input_file) > 0:
        warn("No subdomains found. Skipping httpx.")
        return
    output_file = f"{OUTPUT_DIR}/subdomains_alive.txt"
    cmd = (f"cat {input_file} | httpx -ports 80,443,8080,8000,8888 -threads 200 "
           f"-status-code -title -tech-detect -o {output_file}")
    if run_command(cmd):
        success(f"Alive subdomains saved to {output_file}")
        REPORT_LINES.append(f"httpx → {output_file}")

def step_7_naabu():
    log("STEP 7: Running naabu port scan", YELLOW)
    install_tool("naabu", "sudo apt install -y naabu || go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    input_file = f"{OUTPUT_DIR}/subdomains_alive.txt"
    if not os.path.exists(input_file):
        warn("No alive subdomains. Skipping naabu.")
        return
    output_file = f"{OUTPUT_DIR}/naabu_scan.txt"
    cmd = f"naabu -list {input_file} -c 50 -nmap-cli 'nmap -sV -sC -oN {OUTPUT_DIR}/naabu_nmap.txt' -o {output_file}"
    if run_command(cmd):
        success(f"Naabu scan saved to {output_file}")
        REPORT_LINES.append(f"naabu → {output_file}")

def step_8_dirsearch():
    log("STEP 8: Running dirsearch on alive subdomains", YELLOW)
    if not shutil.which("dirsearch"):
        warn("dirsearch not found. Install manually: pip3 install dirsearch")
        return
    input_file = f"{OUTPUT_DIR}/subdomains_alive.txt"
    if not os.path.exists(input_file):
        warn("No alive subdomains. Skipping dirsearch.")
        return
    output_file = f"{OUTPUT_DIR}/dirsearch_results.txt"
    cmd = (f"dirsearch -l {input_file} -x 500,582,429,484,400 -R 5 --random-agent "
           f"-t 100 -F -o {output_file} -w ./payloads/onelistforallshort.txt")
    if run_command(cmd):
        success(f"Dirsearch results saved to {output_file}")
        REPORT_LINES.append(f"dirsearch → {output_file}")

def step_9_gau():
    log("STEP 9: Fetching URLs with gau", YELLOW)
    install_tool("gau", "go install github.com/lc/gau/v2/cmd/gau@latest")
    input_file = f"{OUTPUT_DIR}/subdomains_alive.txt"
    if not os.path.exists(input_file):
        warn("No alive subdomains. Skipping gau.")
        return
    output_file = f"{OUTPUT_DIR}/gau_urls.txt"
    cmd = f"cat {input_file} | gau --o {output_file}"
    if run_command(cmd):
        success(f"GAU URLs saved to {output_file}")
        REPORT_LINES.append(f"gau → {output_file}")

def step_10_uro():
    log("STEP 10: Filtering URLs with uro", YELLOW)
    install_tool("uro", "go install github.com/kh4sh3i/uro@latest")
    input_file = f"{OUTPUT_DIR}/gau_urls.txt"
    if not os.path.exists(input_file):
        warn("No URLs from gau. Skipping uro.")
        return
    filtered = f"{OUTPUT_DIR}/filtered_params.txt"
    js_out = f"{OUTPUT_DIR}/js_files.txt"
    run_command(f"cat {input_file} | uro -o {filtered}")
    run_command(f"cat {filtered} | grep -i '.js' | uro -o {js_out}")
    success(f"Filtered URLs → {filtered}")
    success(f"JS Files → {js_out}")
    REPORT_LINES.append(f"uro (params) → {filtered}")
    REPORT_LINES.append(f"uro (js) → {js_out}")

def step_11_secretfinder():
    log("STEP 11: Running SecretFinder on JS files", YELLOW)
    js_file = f"{OUTPUT_DIR}/js_files.txt"
    if not os.path.exists(js_file):
        warn("No JS files found. Skipping SecretFinder.")
        return
    output_file = f"{OUTPUT_DIR}/js_secrets.txt"
    cmd = (f"cat {js_file} | while read url; do "
           f"python3 /home/ashmar/playgorund/secretfinder/SecretFinder.py -i \"$url\" -o cli; "
           f"echo '--- $url ---'; done > {output_file}")
    if run_command(cmd):
        success(f"Secrets extracted → {output_file}")
        REPORT_LINES.append(f"SecretFinder → {output_file}")

def step_12_nuclei():
    log("STEP 12: Running Nuclei scan", YELLOW)
    install_tool("nuclei", "sudo apt install -y nuclei || go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    input_file = f"{OUTPUT_DIR}/filtered_params.txt"
    if not os.path.exists(input_file):
        warn("No input URLs for nuclei. Skipping.")
        return
    output_file = f"{OUTPUT_DIR}/nuclei_findings.txt"
    templates = "/home/ashmar/playgorund/nuclei-templates/"
    cmd = (f"nuclei -list {input_file} -c 70 -rl 200 -fhr -lfa "
           f"-t {templates} -o {output_file} -es info")
    if run_command(cmd):
        success(f"Nuclei results → {output_file}")
        REPORT_LINES.append(f"nuclei → {output_file}")

def generate_report():
    log("Generating final report...", GREEN)
    report_file = f"{OUTPUT_DIR}/report_{TARGET}.txt"
    total_time = time.time() - START_TIME
    with open(report_file, "w") as f:
        f.write("\n".join(REPORT_LINES))
        f.write(f"\nTotal Execution Time: {total_time:.2f} seconds\n")
        f.write(f"Findings stored in: {OUTPUT_DIR}/\n")
    success(f"Final report saved: {report_file}")

def main():
    global TARGET
    banner()
    if len(sys.argv) != 2:
        print(f"{RED}Usage: python3 {sys.argv[0]} <target-domain>{RESET}")
        sys.exit(1)
    
    TARGET = sys.argv[1].strip().lower()
    if not re.match(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.[a-z]{2,}$', TARGET):
        error("Invalid domain format.")
        sys.exit(1)

    setup_environment()

    try:
        step_1_manual_recon()
        step_2_google_dorks()
        step_3_metadata()
        step_4_subfinder()
        step_5_crt_sh()
        # Merge all subdomains
        os.system(f"cat {OUTPUT_DIR}/subdomains_*.txt 2>/dev/null | anew {OUTPUT_DIR}/subdomains_all.txt")
        step_6_httpx()
        step_7_naabu()
        step_8_dirsearch()
        step_9_gau()
        step_10_uro()
        step_11_secretfinder()
        step_12_nuclei()
    except KeyboardInterrupt:
        error("Recon interrupted by user.")
    except Exception as e:
        error(f"Unexpected error: {e}")
    finally:
        generate_report()
        log(f"Recon completed in {(time.time() - START_TIME):.2f} seconds.", GREEN)

if __name__ == "__main__":
    main()
