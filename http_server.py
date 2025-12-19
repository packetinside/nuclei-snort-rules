import json
from flask import Flask, request, make_response
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)

# 요청 규칙 저장소
rules = {}

# [수정] 명시적으로 줄바꿈 문자(\n)와 들여쓰기 공백을 포함하여 정의
SECURITY_NOTICE_FOOTER = (
    "\n\n"  # 본문과 구분하기 위한 빈 줄 2개
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "    <title>Test Server</title>\n"
    "    <style>\n"
    "        body { font-family: monospace; padding: 20px; background: #fff; color: #000; }\n"
    "        hr { border: 0; border-bottom: 1px dashed #ccc; margin: 20px 0; }\n"
    "        .hidden-msg { color: #888; font-size: 0.9em; }\n"
    "    </style>\n"
    "</head>\n"
    "<body>\n"
    "    <h1>Forbidden</h1>\n"
    "    <p>You do not have permission to access this resource.</p>\n"
    "    <hr>\n"
    "    <div class=\"hidden-msg\">\n"
    "        <strong>[SECURITY NOTICE]</strong><br>\n"
    "        본 데이터는 실제 공격이 아니며, 탐지 규칙 테스트를 위해 생성되었습니다.<br>\n"
    "        (This packet is generated for detection testing purposes only.)<br><br>\n"
    "        &copy; 2025 PACKET INSIDE. All Rights Reserved.\n"
    "    </div>\n"
    "</body>\n"
    "</html>"
)

def load_rules(file_path="responses.json"):
    global rules
    rules.clear()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            method = item.get("method", "GET").upper()
            url = item.get("url", "/").strip()
            status = item.get("response_code", 200)
            body = item.get("response_body", "")
            headers = item.get("response_headers", {})
            source = item.get("source_file", "")
            rules[(method, url)] = {
                "status": status,
                "body": body,
                "headers": headers,
                "source": source
            }
        print(f"[*] JSON 규칙 로드 완료 (총 {len(rules)}개)")
    except Exception as e:
        print(f"[!] 규칙 로드 오류: {e}")

@app.before_request
def before_request():
    if request.path == "/reload":
        return None

    key = (request.method, request.path)

    # 1. 규칙에 매칭되는 경우
    if key in rules:
        rule = rules[key]
        
        # 원본 본문 + 보안 안내 문구 결합
        original_body = rule.get("body", "")
        combined_body = str(original_body) + SECURITY_NOTICE_FOOTER
        
        resp = make_response(combined_body, rule.get("status", 200))
        
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"

        if "headers" in rule:
            for k, v in rule["headers"].items():
                resp.headers[k] = v
            
        return resp

    # 2. 매칭되는 규칙이 없을 경우 (기본 응답)
    # SECURITY_NOTICE_FOOTER 변수 앞의 줄바꿈(\n\n)을 제거(.strip())하고 본문으로 사용
    return make_response(
        SECURITY_NOTICE_FOOTER.strip(),
        200
    )

@app.after_request
def hide_server_header(response):
    response.headers['Server'] = 'Apache/2.4.52 (Unix)' 
    return response

@app.route("/reload", methods=["POST"])
def reload_rules():
    load_rules()
    return "Rules reloaded!\n"

if __name__ == "__main__":
    load_rules()
    
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    WSGIRequestHandler.server_version = "Apache/2.4.52 (Unix)"
    WSGIRequestHandler.sys_version = ""

    app.run(host="0.0.0.0", port=80)