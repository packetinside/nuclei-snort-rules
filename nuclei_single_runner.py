import os
import re
import yaml
import time
import random
import string
import subprocess
import threading
import sys
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP

# ==========================================
# [설정] 실행할 단일 템플릿 파일 경로 지정
# ==========================================
TARGET_TEMPLATE = r"C:\Users\USER\nuclei-templates\http\cves\2017\CVE-2017-17562.yaml"

# [설정] 사용자 정의 변수 생성 규칙 (복합 패턴 지원)
# "id": "{{rand_numeric(4)}}",
CUSTOM_VARS_CONFIG = {
    "email": "{{rand_alpha(6)}}@{{rand_alpha(5)}}.com",  
    "username": "{{rand_alpha(6)}}",              
    "password": "{{rand_mixed(8)}}",
    #"user": "{{rand_alpha(6)}}",
    #"pass": "{{rand_mixed(8)}}",
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
    #"RootURL": "/",
    "ROotURL": "/",
    "useragent": "{{rand_mixed(6)}}",
    "jobid": "{{rand_numeric(5)}}",
    "appid": "{{rand_mixed(10)}}",
    "Scheme": "http://wwww.victim.com",
    "padstr": "{{rand_mixed(20)}}"
}

# [기타 설정]
TARGET_IP = "www.victim.com"
#TARGET_IP = "172.16.50.207"
TARGET_URL = f"http://{TARGET_IP}"
INTERFACE = "Intel(R) Ethernet Connection (17) I219-LM" 

LOCAL_TEMPLATE_ROOT = r"C:\Users\USER\nuclei-templates"
OUTPUT_DIR_PCAP = "./pcaps"
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# PCAP IP/MAC 변경 설정
NEW_SRC_IP = "192.168.0.100"
NEW_DST_IP = "10.10.10.200"
NEW_SRC_MAC = "00:11:22:33:44:55"
NEW_DST_MAC = "AA:BB:CC:DD:EE:FF"
# ==========================================

def ensure_directories():
    if not os.path.exists(OUTPUT_DIR_PCAP): os.makedirs(OUTPUT_DIR_PCAP)

# --- [기능] PCAP 정제 ---
def clean_pcap_file(input_file):
    if not os.path.exists(input_file): return False
    
    temp_filtered = input_file.replace(".pcap", "_filtered.pcap")
    is_tshark_success = False

    if os.path.exists(TSHARK_PATH):
        filter_expr = "not tcp.analysis.retransmission and not tcp.analysis.duplicate_ack and not tcp.analysis.fast_retransmission"
        cmd = [TSHARK_PATH, "-r", input_file, "-Y", filter_expr, "-w", temp_filtered, "-2"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            is_tshark_success = True
        except: pass

    target_file = temp_filtered if is_tshark_success and os.path.exists(temp_filtered) else input_file
    
    try:
        packets = rdpcap(target_file)
        new_packets = []
        original_client_ip = None
        
        for pkt in packets:
            if pkt.haslayer(IP):
                original_client_ip = pkt[IP].src
                break
        
        if not original_client_ip:
            if is_tshark_success and os.path.exists(temp_filtered): os.remove(temp_filtered)
            return False

        for pkt in packets:
            if pkt.haslayer(IP):
                if pkt[IP].src == original_client_ip:
                    pkt[IP].src = NEW_SRC_IP
                    pkt[IP].dst = NEW_DST_IP
                    src_mac, dst_mac = NEW_SRC_MAC, NEW_DST_MAC
                else:
                    pkt[IP].src = NEW_DST_IP
                    pkt[IP].dst = NEW_SRC_IP
                    src_mac, dst_mac = NEW_DST_MAC, NEW_SRC_MAC
                del pkt[IP].chksum
                if pkt.haslayer(Ether):
                    pkt[Ether].src = src_mac
                    pkt[Ether].dst = dst_mac
            if pkt.haslayer(TCP): del pkt[TCP].chksum
            elif pkt.haslayer(UDP): del pkt[UDP].chksum
            new_packets.append(pkt)
        
        wrpcap(input_file, new_packets)
    except Exception as e:
        print(f"   [Clean] Scapy 처리 오류: {e}")
    finally:
        if is_tshark_success and os.path.exists(temp_filtered):
            os.remove(temp_filtered)
    return True

# --- 유틸리티 함수 (랜덤 생성 로직) ---
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
    """YAML 파일 내 변수 자동 추출"""
    extracted = set()
    if 'http' in yaml_data:
        for req in yaml_data['http']:
            targets = []
            if 'raw' in req: targets.extend(req['raw'])
            if 'path' in req: targets.extend(req['path'])
            for t in targets:
                matches = re.findall(r'{{(.*?)}}', t)
                for match in matches:
                    clean = re.split(r'\(|\)', match)[0] if '(' in match else match
                    extracted.add(clean)
    
    defined_vars = list(yaml_data.get('variables', {}).keys())
    built_in_vars = ['BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'Scheme', 
                     'randstr', 'randstring', 'interactsh-url', 'os', 'to_lower', 
                     'rand_text_alpha', 'md5', 'base64']
    
    exclude_list = built_in_vars + list(CUSTOM_VARS_CONFIG.keys())
    return [v for v in extracted if v not in defined_vars and v not in exclude_list]

def capture_packets(pcap_path, target_ip, duration, interface):
    try:
        bpf = f"host {target_ip} and (tcp port 80 or tcp port 443)"
        sniff(filter=bpf, iface=interface, timeout=duration, prn=lambda x: wrpcap(pcap_path, x, append=True))
    except: pass

def process_template(file_path):
    print(f"\n{'='*60}")
    print(f"🚀 처리 시작: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"   [Error] 파일을 찾을 수 없습니다.")
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f: data = yaml.safe_load(f)
    except: return

    # 1. 커스텀 변수 처리
    nuclei_args = []
    print(f"   [Vars] 변수 생성:")
    for var_name, rule in CUSTOM_VARS_CONFIG.items():
        final_val = generate_var_value(rule)
        print(f"      - {var_name}: {final_val}")
        nuclei_args.extend(["-var", f"{var_name}={final_val}"])

    # 2. 자동 추출 변수 추가
    needed_vars = extract_variables_keys(data)
    for var in needed_vars:
        nuclei_args.extend(["-var", f"{var}={rand_mixed(6)}"])

    # 3. PCAP 캡처 시작
    base_name = os.path.basename(file_path).replace('.yaml', '')
    pcap_filename = f"{base_name.upper()}.pcap"
    pcap_full_path = os.path.join(OUTPUT_DIR_PCAP, pcap_filename)

    if os.path.exists(pcap_full_path): os.remove(pcap_full_path)

    capture_thread = threading.Thread(target=capture_packets, args=(pcap_full_path, TARGET_IP, 10, INTERFACE))
    capture_thread.start()
    time.sleep(2)
    
    # 4. Nuclei 실행
    cmd = ["nuclei", "-t", file_path, "-u", TARGET_URL, "-nc", "-code", "--debug"] + nuclei_args
    print(f"   [Nuclei] 실행 중...")
    
    try:
        # 출력 캡처 없이 실행 (콘솔에 결과 표시됨)
        subprocess.run(cmd, timeout=20)
    except Exception as e:
        print(f"   [Error] Nuclei 실행 중 오류: {e}")
    
    capture_thread.join()
    
    # 5. PCAP 정제
    clean_pcap_file(pcap_full_path)
    print(f"🚀 처리 완료. (PCAP: {pcap_full_path})")

def main():
    ensure_directories()
    process_template(TARGET_TEMPLATE)

if __name__ == "__main__":
    main()