import os
import re
import yaml
import time
import random
import string
import subprocess
import threading
import sys
import json
import hashlib
import google.generativeai as genai
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP

# ==========================================
# [설정] 사용자 정의 변수 생성 규칙
# ==========================================
CUSTOM_VARS_CONFIG = {
    "email": "{{rand_alpha(6)}}@{{rand_alpha(5)}}.com",  
    "username": "{{rand_alpha(6)}}",              
    "password": "{{rand_mixed(8)}}",
    "user": "{{rand_alpha(6)}}",
    "pass": "{{rand_mixed(8)}}",
    "bucket": "{{rand_mixed(4)}}-{{rand_mixed(8)}}-{{rand_mixed(4)}}",
    "access_key_id": "{{rand_mixed(12)}}",
    "object": "{{rand_mixed(5)}}.txt",
    "region": "",
    "token": "{{rand_mixed(20)}}",
    "log_id": "{{rand_numeric(2)}}",
    "filename": "{{rand_alpha(8)}}",
    "fileName": "{{rand_alpha(8)}}",
    "marker": "malicious",
    "path": "wp-admin/",
    "api_key": "{{rand_mixed(12)}}",
    "AUTH_SESSION_ID_LEGACY": "{{rand_mixed(20)}}",
    "RELAYSTATE": "https://myapp.com",
    "padstr": "{{rand_mixed(10)}}",
    "form_token": "{{rand_mixed(10)}}",
    "num": "{{rand_numeric(4)}}",
    "RootURL": "/",
    "ROotURL": "/",
    "useragent": "{{rand_mixed(6)}}",
    "jobid": "{{rand_numeric(5)}}",
    "appid": "{{rand_mixed(10)}}",
}


# ==========================================
# [설정] 환경에 맞게 수정하세요
# ==========================================
USE_GEMINI = False                               # Gemini 사용 여부 (False면 AI 스킵)
# [주의] API 키가 코드에 노출되지 않도록 환경 변수 사용을 권장합니다.
GEMINI_API_KEY = "YOUR_API_KEY_HERE"            

TARGET_IP = "www.victim.com"
TARGET_URL = f"http://{TARGET_IP}"

# 윈도우 인터페이스 이름
INTERFACE = "Intel(R) Ethernet Connection (17) I219-LM" 

# [경로 설정]
LOCAL_TEMPLATE_ROOT = r"C:\Users\secne\nuclei-templates"
SEARCH_START_DIR = r"C:\Users\secne\nuclei-templates\http\cves" 

GITHUB_BASE_URL = "https://github.com/packetinside/nuclei-templates/blob/main"

OUTPUT_DIR_MD = "./_cves"
OUTPUT_DIR_PCAP = "./pcaps"
STATE_FILE = "processed_state.json"
GIT_BRANCH = "main"

# [PCAP 정제 설정]
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

NEW_SRC_IP = "192.168.0.100"
NEW_DST_IP = "10.10.10.200"
NEW_SRC_MAC = "00:11:22:33:44:55"
NEW_DST_MAC = "AA:BB:CC:DD:EE:FF"
# ==========================================

if USE_GEMINI:
    if os.environ.get("GOOGLE_API_KEY"):
        genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    else:
        genai.configure(api_key=GEMINI_API_KEY)
    
    # 존재하는 유효한 모델명으로 변경 (gemini-2.5-pro는 현재 비표준)
    model = genai.GenerativeModel('gemini-2.5-pro') 

def ensure_directories():
    if not os.path.exists(OUTPUT_DIR_MD): os.makedirs(OUTPUT_DIR_MD)
    if not os.path.exists(OUTPUT_DIR_PCAP): os.makedirs(OUTPUT_DIR_PCAP)

# --- [기능] 상태 관리 ---
def get_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f: return json.load(f)
    return {}

def save_state(state):
    with open(STATE_FILE, 'w') as f: json.dump(state, f, indent=4)

# --- ANSI 코드 제거 함수 ---
def clean_ansi_codes(text):
    """로그에서 ANSI 색상 코드를 제거합니다."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# --- [기능] Git 자동 업로드 ---
def git_push_changes(message):
    print(f"\n[Git] GitHub 업로드를 시작합니다...")
    try:
        subprocess.run(["git", "add", "."], check=True)
        try:
            subprocess.run(["git", "commit", "-m", message], check=True, stdout=subprocess.DEVNULL)
            print(f"   [Git] 커밋 완료: {message}")
        except subprocess.CalledProcessError:
            print("   [Git] 변경된 사항이 없습니다.")
            return
        subprocess.run(["git", "push", "origin", GIT_BRANCH], check=True)
        print(f"   [Git] 푸시 성공!")
    except Exception as e:
        print(f"   [Git] 오류 발생: {e}")

# --- [기능] PCAP 정제 (Tshark + Scapy) ---
def clean_pcap_file(input_file):
    if not os.path.exists(input_file):
        print(f"   [Clean] 건너뜀: PCAP 파일이 없습니다. ({os.path.basename(input_file)})")
        return False

    print(f"   [Clean] PCAP 정제 시작: {os.path.basename(input_file)}")
    temp_filtered = input_file.replace(".pcap", "_filtered.pcap")
    is_tshark_success = False

    if os.path.exists(TSHARK_PATH):
        # TCP 재전송, 중복 ACK 등을 제거하여 깔끔하게 만듦
        filter_expr = "not tcp.analysis.retransmission and not tcp.analysis.duplicate_ack and not tcp.analysis.fast_retransmission"
        cmd = [TSHARK_PATH, "-r", input_file, "-Y", filter_expr, "-w", temp_filtered, "-2"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            is_tshark_success = True
        except: 
            pass
    else:
        print(f"   [Clean] 경고: Tshark를 찾을 수 없습니다.")

    target_file = temp_filtered if is_tshark_success and os.path.exists(temp_filtered) else input_file
    
    try:
        packets = rdpcap(target_file)
        new_packets = []
        original_client_ip = None
        
        # 첫 번째 IP 패킷을 찾아 출발지를 클라이언트로 간주
        for pkt in packets:
            if pkt.haslayer(IP):
                original_client_ip = pkt[IP].src
                break
        
        if not original_client_ip:
            if is_tshark_success and os.path.exists(temp_filtered): os.remove(temp_filtered)
            return False

        for pkt in packets:
            if pkt.haslayer(IP):
                # IP/MAC 주소 익명화/변경
                if pkt[IP].src == original_client_ip:
                    pkt[IP].src = NEW_SRC_IP
                    pkt[IP].dst = NEW_DST_IP
                    src_mac, dst_mac = NEW_SRC_MAC, NEW_DST_MAC
                else:
                    pkt[IP].src = NEW_DST_IP
                    pkt[IP].dst = NEW_SRC_IP
                    src_mac, dst_mac = NEW_DST_MAC, NEW_SRC_MAC
                
                # 체크섬 삭제 (Scapy가 다시 계산하도록)
                del pkt[IP].chksum
                if pkt.haslayer(Ether):
                    pkt[Ether].src = src_mac
                    pkt[Ether].dst = dst_mac
            
            if pkt.haslayer(TCP): del pkt[TCP].chksum
            elif pkt.haslayer(UDP): del pkt[UDP].chksum
            new_packets.append(pkt)
        
        wrpcap(input_file, new_packets)
        print("   [Clean] 완료.")
    except Exception as e:
        print(f"   [Clean] Scapy 처리 오류: {e}")
    finally:
        if is_tshark_success and os.path.exists(temp_filtered):
            os.remove(temp_filtered)
    return True

# --- 유틸리티 함수 ---
def rand_alpha(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def rand_numeric(length=8):
    return ''.join(random.choice(string.digits) for _ in range(length))

def rand_mixed(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_var_value(rule):
    """규칙에 따라 랜덤 값(복합 패턴 포함) 또는 고정 값 반환"""
    
    if isinstance(rule, int):
        return rand_mixed(rule)
    
    if isinstance(rule, str):
        def replacer(match):
            func_name = match.group(1)
            length = int(match.group(2))
            
            if func_name == "rand_alpha": return rand_alpha(length)
            elif func_name == "rand_numeric": return rand_numeric(length)
            elif func_name in ["rand_mixed", "rand_base"]: return rand_mixed(length)
            return match.group(0)
        
        pattern = r'\{\{\s*(rand_[a-z]+|rand_base)\((\d+)\)\s*\}\}'
        return re.sub(pattern, replacer, rule)
    
    return rand_mixed(8)

def extract_variables_keys(yaml_data):
    extracted = set()
    if 'http' in yaml_data:
        for req in yaml_data['http']:
            targets = []
            if 'raw' in req: targets.extend(req['raw'])
            if 'path' in req: targets.extend(req['path'])
            for t in targets:
                # {{var}} 형태 추출
                matches = re.findall(r'{{(.*?)}}', t)
                for match in matches:
                    clean = re.split(r'\(|\)', match)[0] if '(' in match else match
                    extracted.add(clean)
    defined_vars = list(yaml_data.get('variables', {}).keys())
    built_in_vars = ['BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'Scheme', 'randstr', 'randstring', 'interactsh-url', 'os', 'to_lower', 'rand_text_alpha', 'md5', 'base64']
    return [v for v in extracted if v not in defined_vars and v not in built_in_vars]

def extract_request_from_log(log_content):
    # clean_ansi_codes 함수가 정의되어 있어야 호출 가능
    clean_log = clean_ansi_codes(log_content)
    requests = []
    current_req = []
    is_capturing = False
    
    # 1. 마커 기반 파싱 (Nuclei -debug-req 출력 분석)
    for line in clean_log.splitlines():
        stripped = line.strip()
        # 불필요한 로그 제외
        if "[INF]" in line or "[WRN]" in line or "[ERR]" in line:
            if "Scan completed" in line: is_capturing = False
            continue
            
        if "[Request]" in line or "Dump Request" in line:
            is_capturing = True
            if current_req:
                requests.append("\n".join(current_req).strip())
                current_req = []
            continue
        if "[Response]" in line or "Dump Response" in line:
            is_capturing = False
            if current_req:
                requests.append("\n".join(current_req).strip())
                current_req = []
            continue
        if is_capturing and not stripped.startswith("["):
            current_req.append(line)

    if current_req:
        requests.append("\n".join(current_req).strip())
    
    # 2. 정규식 기반 Fallback (Nuclei 포맷 변경 대비)
    if not requests:
        pattern = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+.*?\s+HTTP/\d\.\d', re.MULTILINE)
        matches = list(pattern.finditer(clean_log))
        for i, match in enumerate(matches):
            start_idx = match.start()
            end_idx = matches[i+1].start() if i + 1 < len(matches) else len(clean_log)
            chunk = clean_log[start_idx:end_idx]
            
            # 응답(HTTP/1.1 200 OK 등)이 나오기 전까지만 자름
            resp_match = re.search(r'^HTTP/\d\.\d\s+\d{3}', chunk, re.MULTILINE)
            if resp_match:
                chunk = chunk[:resp_match.start()]
                
            lines = chunk.splitlines()
            filtered_lines = [l for l in lines if not ("[INF]" in l or "[WRN]" in l or "[ERR]" in l)]
            clean_chunk = "\n".join(filtered_lines).strip()
            
            if clean_chunk:
                requests.append(clean_chunk)
            
    return requests

def capture_packets(pcap_path, target_ip, duration, interface):
    print(f"   [PCAP] Sniffing on {interface} ({duration}s)...")
    try:
        # Tshark filter와 유사하게 HTTP 포트 위주로 캡처
        bpf = f"host {target_ip} and (tcp port 80 or tcp port 443)"
        pkts = sniff(filter=bpf, iface=interface, timeout=duration)
        wrpcap(pcap_path, pkts)
    except Exception as e:
        print(f"   [PCAP] Error: {e}")

def generate_snort_rules_via_ai(cve_id, description, request_text):
    if not USE_GEMINI: return "N/A", "N/A"
    
    prompt = f"""
    You are a network security specialist. Create Snort 2 & 3 rules based on the provided vulnerability info and HTTP request.
    
    [CVE ID]: {cve_id}
    [Description]: {description}
    [HTTP Request]: 
    {request_text[:2500]} 

    Please output strictly in this format:
    ---SNORT2---
    (Your Snort 2 rule here)
    ---SNORT3---
    (Your Snort 3 rule here)
    """
    try:
        resp = model.generate_content(prompt).text
        if "---SNORT2---" in resp:
            parts = resp.split("---SNORT3---")
            s2 = parts[0].replace("---SNORT2---", "").strip()
            s3 = parts[1].strip() if len(parts) > 1 else "N/A"
            return s2, s3
    except Exception as e:
        print(f"   [Gemini] Error: {e}")
        pass
    return "N/A", "N/A"

def generate_github_url(local_file_path):
    try:
        rel = os.path.relpath(local_file_path, LOCAL_TEMPLATE_ROOT).replace("\\", "/")
        return f"{GITHUB_BASE_URL}/{rel}"
    except: return "N/A"

def create_markdown_file(yaml_path, yaml_data, pcap_filename, requests_content, snort2, snort3, pcap_relative_path):
    info = yaml_data.get('info', {})
    file_basename = os.path.basename(yaml_path).replace('.yaml', '')
    
    cve_id = info.get('id', file_basename.upper())
    title = info.get('name', cve_id)
    nuclei_url = generate_github_url(yaml_path)
    
    front_matter = {
        'layout': 'post',
        'cve_id': cve_id,
        'title': title,
        'pcap': True,
        'pcap_path': pcap_relative_path,
        'nuclei_url': nuclei_url,
    }

    exclude_keys = ['name', 'id', 'description']
    for key, value in info.items():
        if key not in exclude_keys:
            if key == 'tags' and isinstance(value, str):
                value = [tag.strip() for tag in value.split(',')]
            front_matter[key] = value

    def clean_yaml_string(val):
        if isinstance(val, str):
            val = val.replace("\\!", "!").replace("\\(", "(").replace("\\)", ")").replace("\\,", ",").replace("\\'", "'")
            val = val.replace('"', '\\"')
        return val

    fm_text = "---\n"
    for k, v in front_matter.items():
        if isinstance(v, list):
            clean_list = [clean_yaml_string(item) if isinstance(item, str) else item for item in v]
            fm_text += f"{k}:\n"
            for item in clean_list: fm_text += f'  - "{item}"\n'
        elif isinstance(v, dict):
            fm_text += f"{k}:\n"
            for sk, sv in v.items():
                if isinstance(sv, str): fm_text += f'  {sk}: "{clean_yaml_string(sv)}"\n'
                else: fm_text += f"  {sk}: {sv}\n"
        elif isinstance(v, bool):
            fm_text += f"{k}: {'true' if v else 'false'}\n"
        else:
            if isinstance(v, str): fm_text += f'{k}: "{clean_yaml_string(v)}"\n'
            else: fm_text += f"{k}: {v}\n"
    
    fm_text += f"snort2_rule: |\n"
    for line in snort2.splitlines(): fm_text += f"  {line}\n"
    fm_text += f"snort3_rule: |\n"
    for line in snort3.splitlines(): fm_text += f"  {line}\n"
    fm_text += "---\n"

    description = info.get('description', 'No description provided.')
    
    http_section = ""
    if isinstance(requests_content, list) and requests_content:
        for req in requests_content:
            http_section += f"```nohighlight\n{req}\n```\n\n"
    else:
        req_str = requests_content if isinstance(requests_content, str) else "No request captured."
        http_section = f"```nohighlight\n{req_str}\n```"

    md_content = f"""{fm_text}

## 🔍 Vulnerability Description
{description}

## 🌐 HTTP Request
{http_section}
"""
    
    # 경로 생성 로직 안전하게 변경
    year_match = re.search(r'CVE-(\d{4})-', cve_id, re.IGNORECASE)
    year_folder = year_match.group(1) if year_match else "others"
    
    # OUTPUT_DIR_MD가 ./_cves 이므로, ./_cves/2024 와 같이 생성
    target_dir = os.path.join(OUTPUT_DIR_MD, year_folder)
    
    if not os.path.exists(target_dir): os.makedirs(target_dir)

    md_filename = os.path.join(target_dir, f"{file_basename.lower()}.md")
    with open(md_filename, 'w', encoding='utf-8') as f: f.write(md_content)
    print(f"   [Markdown] 생성 완료: {md_filename}")

def process_template(file_path):
    print(f"\n{'='*60}")
    print(f"🚀 처리 중: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f: data = yaml.safe_load(f)
    except Exception as e:
        print(f"   [Error] YAML 로드 실패: {e}")
        return

    # 1. 커스텀 변수 처리 (사용자 정의 값 우선 적용)
    nuclei_args = []
    print(f"   [Vars] 변수 생성:")
    for var_name, rule in CUSTOM_VARS_CONFIG.items():
        final_val = generate_var_value(rule)
        print(f"      - {var_name}: {final_val}")
        nuclei_args.extend(["-var", f"{var_name}={final_val}"])

    # 2. 자동 추출 변수 추가
    needed_vars = extract_variables_keys(data)
    for var in needed_vars:
        # 이미 CUSTOM_VARS_CONFIG에서 처리한 변수라면 건너뜁니다!
        if var in CUSTOM_VARS_CONFIG:
            continue
            
        # 정의되지 않은 새로운 변수만 랜덤 값 할당
        nuclei_args.extend(["-var", f"{var}={rand_mixed(6)}"])
        
    base_name = os.path.basename(file_path).replace('.yaml', '')
    
    cve_match = re.search(r'CVE-(\d{4})-', base_name, re.IGNORECASE)
    year_folder = cve_match.group(1) if cve_match else "others"
    pcap_dir = os.path.join(OUTPUT_DIR_PCAP, year_folder)
    if not os.path.exists(pcap_dir): os.makedirs(pcap_dir)
    
    pcap_filename = f"{base_name.upper()}.pcap"
    pcap_full_path = os.path.join(pcap_dir, pcap_filename)
    pcap_web_path = f"/pcaps/{year_folder}/{pcap_filename}"

    if os.path.exists(pcap_full_path): os.remove(pcap_full_path)
    
    # [캡처 쓰레드 시작]
    capture_thread = threading.Thread(target=capture_packets, args=(pcap_full_path, TARGET_IP, 10, INTERFACE))
    capture_thread.start()
    time.sleep(2) 
    
    # [Nuclei 실행]
    cmd = ["nuclei", "-t", file_path, "-u", TARGET_URL, "-debug-req", "-nc", "-code"] + nuclei_args
    print(f"   [Nuclei] 공격 실행 중...")
    try:
        # errors='replace'로 인코딩 오류 방지
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
        nuclei_output = result.stdout + (result.stderr if result.stderr else "")
    except Exception as e:
        print(f"   [Nuclei] 실행 오류: {e}")
        nuclei_output = ""
    
    capture_thread.join()

    # PCAP 정제
    clean_pcap_file(pcap_full_path)

    # 로그에서 요청 추출
    actual_requests = extract_request_from_log(nuclei_output)
    
    if actual_requests:
        req_for_ai = "\n\n".join(actual_requests)
    else:
        req_for_ai = "No request captured."

    print("   [Gemini] Rule 생성 중...")
    info = data.get('info', {})
    snort2, snort3 = generate_snort_rules_via_ai(info.get('id', base_name), info.get('description', ''), req_for_ai)
    
    create_markdown_file(file_path, data, pcap_filename, actual_requests, snort2, snort3, pcap_web_path)

def get_sorted_yaml_files_by_year(base_dir):
    target_files = []
    try:
        years = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d)) and d.isdigit() and len(d) == 4]
    except FileNotFoundError:
        print(f"[!] 경로를 찾을 수 없습니다: {base_dir}")
        return []

    years.sort(key=int, reverse=True)
    for year in years:
        year_path = os.path.join(base_dir, year)
        files = [f for f in os.listdir(year_path) if f.endswith('.yaml')]
        def get_cve_number(filename):
            match = re.search(r'CVE-\d{4}-(\d+)', filename, re.IGNORECASE)
            return int(match.group(1)) if match else 0
        files.sort(key=get_cve_number, reverse=True)
        for f in files: target_files.append(os.path.join(year_path, f))
    return target_files

def main():
    ensure_directories()
    state = load_state()
    
    print(f"[*] YAML 검색 시작: {SEARCH_START_DIR}")
    yaml_files = get_sorted_yaml_files_by_year(SEARCH_START_DIR)

    if not yaml_files:
        print("[!] 처리할 파일이 없습니다.")
        return
        
    print(f"[*] 총 {len(yaml_files)}개 템플릿 발견.")
    processed_count = 0
    
    for yaml_file in yaml_files:
        if not os.path.exists(yaml_file):
            print(f"[!] 경고: 파일 접근 불가 (건너뜀): {yaml_file}")
            continue

        try:
            current_hash = get_file_hash(yaml_file)
        except Exception as e:
            print(f"[!] 파일 해시 계산 오류 (건너뜀): {yaml_file}, {e}")
            continue

        file_key = os.path.basename(yaml_file)
        
        # 이전 상태와 해시가 같으면 스킵
        if file_key in state and state[file_key] == current_hash:
           continue
           
        # 처리 시작
        process_template(yaml_file)
        
        # 상태 업데이트
        state[file_key] = current_hash
        processed_count += 1
        save_state(state)

    if processed_count > 0:
        save_state(state)
        print(f"\n[*] 총 {processed_count}개 파일 처리 완료.")
        git_push_changes(f"Auto-update: Processed {processed_count} CVEs")
    else:
        print("\n[*] 업데이트된 파일이 없습니다.")

if __name__ == "__main__":
    main()