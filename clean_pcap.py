import os
import subprocess
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

# ================= 사용자 설정 =================
TARGET_FOLDER = "pcaps"       # 대상 폴더
BACKUP_ORIGINAL = True        # True: 원본 보존(.bak), False: 원본 삭제
TSHARK_CMD = "C:\\Program Files\\Wireshark\\tshark"         # 환경변수에 없다면 "C:\\Program Files\\Wireshark\\tshark.exe" 처럼 전체 경로 입력

# 변경할 주소 정보
NEW_SRC_IP = "192.168.100.10"
NEW_DST_IP = "10.10.10.20"
NEW_SRC_MAC = "00:11:22:33:44:55"
NEW_DST_MAC = "AA:BB:CC:DD:EE:FF"
# =============================================

def filter_packets_with_tshark(input_file, output_file):
    """
    1단계: Tshark를 사용하여 TCP 재전송 및 중복 패킷 제거
    """
    # 필터: 재전송 아님 AND 중복 ACK 아님 AND KeepAlive 아님(선택사항)
    # tcp.analysis.flags filters는 Wireshark의 분석 엔진을 사용하므로 매우 정확함
    filter_expr = "not tcp.analysis.retransmission and not tcp.analysis.duplicate_ack and not tcp.analysis.fast_retransmission"
    
    cmd = [
        TSHARK_CMD,
        "-r", input_file,
        "-Y", filter_expr,
        "-w", output_file
    ]
    
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print("Error: Tshark를 찾을 수 없습니다. Wireshark가 설치되어 있는지 확인하세요.")
        return False

def rewrite_packets_with_scapy(input_file, output_file):
    """
    2단계: Scapy를 사용하여 IP/MAC 주소 변경 및 체크섬 재계산
    """
    try:
        with PcapReader(input_file) as reader, PcapWriter(output_file, append=True, sync=True) as writer:
            for pkt in reader:
                # 1. Ethernet Header (MAC) 변경
                if pkt.haslayer(Ether):
                    pkt[Ether].src = NEW_SRC_MAC
                    pkt[Ether].dst = NEW_DST_MAC

                # 2. IP Header 변경
                if pkt.haslayer(IP):
                    # 체크섬 삭제 (Scapy가 저장 시 자동 재계산)
                    del pkt[IP].chksum
                    pkt[IP].src = NEW_SRC_IP
                    pkt[IP].dst = NEW_DST_IP

                # 3. TCP/UDP 체크섬 삭제 (IP가 바뀌었으므로 필수)
                if pkt.haslayer(TCP):
                    del pkt[TCP].chksum
                elif pkt.haslayer(UDP):
                    del pkt[UDP].chksum

                writer.write(pkt)
        return True
    except Exception as e:
        print(f"Scapy Rewrite Error: {e}")
        return False

def process_pcaps():
    if not os.path.exists(TARGET_FOLDER):
        print(f"폴더를 찾을 수 없습니다: {TARGET_FOLDER}")
        return

    files = [f for f in os.listdir(TARGET_FOLDER) if f.endswith((".pcap", ".pcapng"))]
    print(f"총 {len(files)}개의 파일을 처리합니다...\n")

    for filename in files:
        original_path = os.path.join(TARGET_FOLDER, filename)
        temp_filtered = os.path.join(TARGET_FOLDER, f"temp_1_filter_{filename}")
        temp_rewritten = os.path.join(TARGET_FOLDER, f"temp_2_rewrite_{filename}")
        backup_path = os.path.join(TARGET_FOLDER, f"{filename}.bak")

        print(f"▶ {filename} 처리 시작")

        # 1단계: 정확한 필터링 (Tshark)
        print("   [1/2] TCP 재전송/중복 제거 (Tshark)... ", end="")
        if filter_packets_with_tshark(original_path, temp_filtered):
            print("성공")
        else:
            print("실패 (건너뜀)")
            if os.path.exists(temp_filtered): os.remove(temp_filtered)
            continue

        # 2단계: 주소 변경 (Scapy)
        print("   [2/2] IP/MAC 주소 변경 (Scapy)... ", end="")
        if rewrite_packets_with_scapy(temp_filtered, temp_rewritten):
            print("성공")
            
            # 원본 교체 작업
            if BACKUP_ORIGINAL:
                if os.path.exists(backup_path): os.remove(backup_path)
                os.rename(original_path, backup_path)
                print("   [완료] 원본 백업 후 교체됨")
            else:
                os.remove(original_path)
                print("   [완료] 원본 삭제 후 교체됨")
            
            os.rename(temp_rewritten, original_path)

        else:
            print("실패")

        # 임시 파일 정리
        if os.path.exists(temp_filtered): os.remove(temp_filtered)
        if os.path.exists(temp_rewritten): os.remove(temp_rewritten)
        print("-" * 50)

if __name__ == "__main__":
    process_pcaps()