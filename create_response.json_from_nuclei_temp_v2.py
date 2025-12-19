import os
import yaml
import json
import re
import glob

# ==========================================
# 사용자 설정
# ==========================================
TEMPLATE_DIR = r"C:\Users\USER\nuclei-templates\http\cves"  # 템플릿 경로
OUTPUT_JSON = "responses.json"
# ==========================================

def clean_regex_to_string(regex_pattern):
    """
    정규표현식 패턴을 단순 문자열로 변환하여 응답 본문에 넣을 수 있게 만듭니다.
    완벽한 복원은 불가능하므로, 메타 문자를 제거하고 가독성 있는 텍스트만 남깁니다.
    """
    # 1. 비캡처 그룹 (?:...) 제거하고 내용만 남김
    pattern = re.sub(r'\(\?:(.*?)\)', r'\1', regex_pattern)
    # 2. 시작(^)과 끝($) 앵커 제거
    pattern = pattern.strip('^$')
    # 3. 긍정형 전방탐색 등 복잡한 구문 제거 (단순화)
    pattern = re.sub(r'\(\?.*?\)', '', pattern)
    # 4. 이스케이프 문자 제거 (예: \. -> .)
    pattern = pattern.replace('\\', '')
    # 5. 와일드카드 및 수량자 단순 제거 (예: .*, +)
    pattern = re.sub(r'[\.\*\{\}\+\?]', '', pattern)
    # 6. 대괄호 문자 클래스 단순화 ([a-z] -> a) - 필요시 로직 강화 가능
    pattern = re.sub(r'\[.*?\]', '', pattern)
    
    return pattern.strip()

def parse_dsl(dsl_line, response_data):
    """
    Nuclei DSL 라인을 분석하여 response_data를 업데이트합니다.
    지원: status_code, contains, contains_all, content_type
    """
    # 1. Status Code
    status_match = re.search(r'status_code\s*==\s*(\d+)', dsl_line)
    if status_match:
        response_data['status'] = int(status_match.group(1))
        return

    # 2. 문자열 추출 (따옴표로 묶인 값들 찾기)
    # 예: contains(body, "string") -> "body", "string" 추출됨
    # 정규식으로 인자들을 추출 (이스케이프 된 따옴표 처리 포함)
    args = re.findall(r'(?:["\'])(.*?)(?:["\'])', dsl_line)
    
    if not args:
        return

    # DSL 함수 파악
    is_contains = 'contains' in dsl_line
    target_part = 'body' # 기본 타겟

    # DSL 내의 첫 번째 인자(변수명) 확인 (body, header, all, content_type 등)
    # 정규식 추출 결과에는 변수명이 안 나올 수 있으므로 dsl_line 자체 검사
    if 'content_type' in dsl_line:
        target_part = 'content_type'
    elif 'header' in dsl_line:
        target_part = 'header'
    
    # 추출된 문자열 리스트 순회
    for arg in args:
        # DSL의 변수명(body, all 등)이 문자열로 인식될 수 있으니 건너뜀
        if arg in ['body', 'all', 'data', 'header', 'content_type']:
            continue
            
        # 데이터 삽입
        if target_part == 'content_type':
            response_data['headers']['Content-Type'] = arg
        elif target_part == 'header':
            if ':' in arg:
                k, v = arg.split(':', 1)
                response_data['headers'][k.strip()] = v.strip()
            else:
                response_data['headers']['X-Mock-Info'] = arg
        else: # body
            response_data['body'].append(arg)


def parse_matchers(matchers):
    """
    Nuclei Matcher를 분석하여 예상되는 Body, Headers, Status Code를 추출합니다.
    """
    response_data = {
        "body": [],
        "headers": {},
        "status": 200
    }

    if not matchers:
        return response_data

    for matcher in matchers:
        m_type = matcher.get('type', '')
        m_part = matcher.get('part', 'body')  # 기본값 body
        
        # ---------------------------
        # 1. DSL Matcher
        # ---------------------------
        if m_type == 'dsl':
            for dsl in matcher.get('dsl', []):
                parse_dsl(dsl, response_data)

        # ---------------------------
        # 2. Word Matcher
        # ---------------------------
        elif m_type == 'word':
            words = matcher.get('words', [])
            if m_part == 'header':
                for w in words:
                    if ':' in w:
                        k, v = w.split(':', 1)
                        response_data['headers'][k.strip()] = v.strip()
                    elif '/' in w: # application/json 같은 경우
                        response_data['headers']['Content-Type'] = w
                    else:
                        response_data['headers']['X-Mock-Header'] = w
            else: # body, all
                response_data['body'].extend(words)

        # ---------------------------
        # 3. Regex Matcher (신규 추가)
        # ---------------------------
        elif m_type == 'regex':
            regexes = matcher.get('regex', [])
            for rgx in regexes:
                cleaned_text = clean_regex_to_string(rgx)
                
                if m_part == 'header':
                    # 헤더 정규식 처리 (예: Location: http://...)
                    if ':' in cleaned_text:
                        k, v = cleaned_text.split(':', 1)
                        response_data['headers'][k.strip()] = v.strip()
                    else:
                        # 키:값 형태가 아니면 임시 헤더에 넣음
                        response_data['headers']['X-Regex-Header'] = cleaned_text
                else:
                    # Body 정규식 처리
                    response_data['body'].append(cleaned_text)

        # ---------------------------
        # 4. Status Matcher
        # ---------------------------
        elif m_type == 'status':
            status_list = matcher.get('status', [])
            if status_list:
                response_data['status'] = status_list[0]

    return response_data

def main():
    rules = []
    
    # 모든 YAML 파일 검색
    yaml_files = glob.glob(os.path.join(TEMPLATE_DIR, "**", "*.yaml"), recursive=True)
    print(f"[*] Found {len(yaml_files)} templates. Parsing...")

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception:
            continue

        if 'http' not in data:
            continue

        template_id = data.get('id', os.path.basename(yaml_file))
        
        for req in data['http']:
            method = "GET"
            path = "/"
            
            if 'method' in req:
                method = req['method']
            
            # Raw request 처리
            if 'raw' in req and req['raw']:
                first_line = req['raw'][0].split('\n')[0]
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
            
            # Path 필드 처리
            if 'path' in req:
                path = req['path'][0].replace('{{BaseURL}}', '')
                if not path.startswith('/'):
                    path = '/' + path

            # Matcher 분석
            matchers = req.get('matchers', [])
            parsed_data = parse_matchers(matchers)

            # 응답 본문 조합
            if parsed_data['body']:
                # 리스트의 문자열들을 줄바꿈으로 합침
                response_body = "\n".join(parsed_data['body'])
            else:
                # 매처가 없거나 추출 실패 시 기본 메시지
                response_body = f"PacketInside Mock Server: {template_id}"

            rule = {
                "method": method,
                "url": path,
                "response_code": parsed_data['status'],
                "response_body": response_body,
                "response_headers": parsed_data['headers'],
                "source_file": yaml_file
            }
            rules.append(rule)

    # JSON 저장
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(rules, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Successfully created {OUTPUT_JSON} with {len(rules)} rules.")

if __name__ == "__main__":
    main()