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
        m_part = matcher.get('part', 'body')  # 기본값은 body
        
        # 1. DSL 매처 처리 (contains)
        if m_type == 'dsl':
            for dsl in matcher.get('dsl', []):
                # Status Code 추출 (예: status_code == 404)
                status_match = re.search(r'status_code\s*==\s*(\d+)', dsl)
                if status_match:
                    response_data['status'] = int(status_match.group(1))

                # Body 내용 추출 (예: contains(body, "string"))
                # contains(body, ...) 또는 contains(all, ...) 처리
                body_match = re.search(r'contains\((?:body|all|data),\s*["\'](.*?)["\']\)', dsl, re.IGNORECASE)
                if body_match:
                    response_data['body'].append(body_match.group(1))

                # Header 내용 추출 (예: contains(header, "text/xml"))
                header_match = re.search(r'contains\(header,\s*["\'](.*?)["\']\)', dsl, re.IGNORECASE)
                if header_match:
                    val = header_match.group(1)
                    # "key: value" 형태인 경우
                    if ':' in val:
                        k, v = val.split(':', 1)
                        response_data['headers'][k.strip()] = v.strip()
                    # "text/xml" 처럼 값만 있는 경우 -> Content-Type으로 추정
                    elif '/' in val:
                        response_data['headers']['Content-Type'] = val
                    else:
                        # 키를 알 수 없는 경우 X-Mock-Header에 추가
                        response_data['headers']['X-Mock-Info'] = val

        # 2. Word 매처 처리 (단어 일치)
        elif m_type == 'word':
            words = matcher.get('words', [])
            if m_part == 'body' or m_part == 'all':
                response_data['body'].extend(words)
            
            elif m_part == 'header':
                for w in words:
                    if ':' in w:
                        k, v = w.split(':', 1)
                        response_data['headers'][k.strip()] = v.strip()
                    elif '/' in w:
                        response_data['headers']['Content-Type'] = w
                    else:
                        response_data['headers']['X-Mock-Header'] = w

        # 3. Status 매처 처리
        elif m_type == 'status':
            status_list = matcher.get('status', [])
            if status_list:
                response_data['status'] = status_list[0] # 첫 번째 상태 코드 채택

    return response_data

def main():
    rules = []
    
    # 모든 YAML 파일 검색 (하위 폴더 포함)
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

        # 템플릿 정보
        template_id = data.get('id', os.path.basename(yaml_file))
        
        # HTTP 요청 파싱
        for req in data['http']:
            # 요청 메서드와 경로 추출
            method = "GET" # 기본값
            path = "/"
            
            if 'method' in req:
                method = req['method']
            
            # raw 요청에서 메서드/경로 추출 시도
            if 'raw' in req:
                first_line = req['raw'][0].split('\n')[0]
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
            
            # path 필드 사용 시 (단순화: 첫 번째 경로만 사용)
            if 'path' in req:
                path = req['path'][0].replace('{{BaseURL}}', '')
                if not path.startswith('/'):
                    path = '/' + path

            # Matcher 분석하여 응답 데이터 생성
            matchers = req.get('matchers', [])
            parsed_data = parse_matchers(matchers)

            # 응답 본문 생성 (매처에서 찾은 키워드들을 합침)
            # 만약 매처가 없다면 기본 성공 메시지
            if parsed_data['body']:
                response_body = "\n".join(parsed_data['body'])
            else:
                response_body = f"PacketInside Mock Server: {template_id}"

            # 규칙 추가
            rule = {
                "method": method,
                "url": path,
                "response_code": parsed_data['status'],
                "response_body": response_body,
                "response_headers": parsed_data['headers'], # 헤더 추가됨
                "source_file": yaml_file
            }
            rules.append(rule)

    # JSON 저장
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(rules, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Successfully created {OUTPUT_JSON} with {len(rules)} rules.")

if __name__ == "__main__":
    main()