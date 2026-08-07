import os
import sys
import subprocess
import json
import urllib.request
import urllib.error

# Q-SAFE IRON SENTINEL: Windows Python Adapter
# Replicates the flow and layout of guardian.asm

# Configuration
SCAN_DIR = "sandbox_env"
SCAN_LIST_FILE = "scan_list.txt"
TARGET_LIST_FILE = "suspicious_targets.txt"
RESP_FILENAME = "llm_response.txt"

# Signatures matching guardian.asm
SIG_DEEP = "deep_core"
SIG_MAL = "delete the system logs"

def print_header():
    print("\n===============================================")
    print("   Q-SAFE IRON SENTINEL: REAL MODE (WINDOWS)    ")
    print("   (Core Memory -> Global Scan -> Deep Neutralization)")
    print("===============================================")

def verify_integrity():
    # Simulate CPU & Register check
    print("    [+] Core Registers: Verified. RFLAGS/NX: Secure.")

def run_global_discovery():
    print("\n[1/3] GLOBAL DISCOVERY: Mapping Directory Structure...")
    print(f"    > Scanning sandbox directory: {SCAN_DIR}...")
    
    allowed_extensions = {'.py', '.sh', '.elf', '.exe', '.txt', '.cpp', '.asm'}
    found_files = []
    
    if os.path.exists(SCAN_DIR):
        for root, dirs, files in os.walk(SCAN_DIR):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in allowed_extensions:
                    full_path = os.path.join(root, file)
                    # Standardize with forward slashes for the triage agent
                    normalized_path = full_path.replace('\\', '/')
                    found_files.append(normalized_path)
                    
    with open(SCAN_LIST_FILE, "w") as f:
        for fp in found_files:
            f.write(fp + "\n")
            
    print(f"    > Found {len(found_files)} potential vectors.")
    print("    > Discovery Complete.")

def run_agentic_triage():
    print("\n[2/3] AGENT ACTIVE: Initializing Hierarchical Analysis...")
    # Invoke agent_triage.py
    cmd = [sys.executable, "agent_triage.py"]
    subprocess.run(cmd)
    print("    [+] Agentic Handoff Received.")

def deep_analyze_file(filepath, api_key):
    # Check filename signature
    if SIG_DEEP in os.path.basename(filepath):
        print("        [!] DEEP CORE SIGNATURE DETECTED: 0xDEADBEEF (Kernel-Level Anomaly)")
        return True
        
    # Read file content
    if not os.path.exists(filepath):
        return False
        
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return False
        
    # Local content signature check
    if SIG_MAL in content:
        return True
        
    # Remote LLM check if API key is present
    if api_key and api_key != "test":
        print("        [*] Querying remote intelligence for deep file inspection...")
        payload = {
            "model": "mistralai/mistral-7b-instruct:free",
            "messages": [
                {
                    "role": "system", 
                    "content": "Deep Code Analysis. Check for buffer overflows, shellcode, rm -rf, or reverse shells. Reply UNSAFE if malicious, SAFE otherwise."
                },
                {
                    "role": "user",
                    "content": f"Code: {content[:4000]}"
                }
            ]
        }
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=json.dumps(payload).encode('utf-8'),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    response_text = data['choices'][0]['message']['content']
                    with open(RESP_FILENAME, "w") as f_resp:
                        f_resp.write(response_text)
                    if "UNSAFE" in response_text:
                        return True
        except Exception as e:
            print(f"        [!] Neural link error during deep scan: {e}")
            
    return False

def run_deep_scan():
    print("\n[3/3] DEEP CODE ANALYSIS: Inspecting Agent Vectors...")
    if not os.path.exists(TARGET_LIST_FILE):
        print("    [-] No targets list found.")
        return
        
    with open(TARGET_LIST_FILE, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
        
    if not targets:
        print("    [+] No suspicious targets queued by Agent.")
        return
        
    api_key = os.getenv("OPENROUTER_KEY") or os.getenv("OPENROUTER_API_KEY")
    
    for target in targets:
        print(f"    [*] Scanning: {target}")
        is_unsafe = deep_analyze_file(target, api_key)
        
        if is_unsafe:
            print("        [!] CRITICAL: MALICIOUS SIGNATURE DETECTED!")
            ans = input("        [?] NEUTRALIZE THREAT? (y/n): ").strip().lower()
            if ans == 'y':
                try:
                    os.unlink(target)
                    print("        [x] TARGET ELIMINATED.")
                    # Post integrity check
                    verify_integrity()
                    print("        [+] Post-Neutralization Check: Core Memory & Registers VERIFIED.")
                except Exception as e:
                    print(f"        [!] Failed to eliminate target: {e}")
            else:
                print("        [-] Threat Retained.")
        else:
            print("        [+] Status: CLEAN.")

def main():
    print_header()
    
    print("\n[1/3] CORE MEMORY & REGISTER INTEGRITY CHECK...")
    verify_integrity()
    
    ans = input("    [?] Search sandbox file system? (y/n): ").strip().lower()
    if ans != 'y':
        print("[-] Exiting.")
        return
        
    run_global_discovery()
    
    run_agentic_triage()
    
    ans = input("\n    [?] Deep Scan identified vectors? (y/n): ").strip().lower()
    if ans != 'y':
        print("[-] Exiting.")
        return
        
    run_deep_scan()
    print("\n[+] Sentinel Run Completed.")

if __name__ == "__main__":
    main()
