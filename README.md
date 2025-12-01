# 🛡️ Nuclei 공격 탐지 Snort Rules 아카이브

이 페이지는 주요 CVE 및 취약점에 대한 Nuclei 템플릿 링크와 사용자 정의 Snort 탐지 규칙을 제공합니다.

---

## CVE-2025-0107: [Palo Alto Networks Expedition - OS Command Injection]
> An OS command injection vulnerability in Palo Alto Networks Expedition enables an unauthenticated attacker to run arbitrary OS commands as the www-data user in Expedition, which results in the disclosure of usernames, cleartext passwords, device configurations, and device API keys for firewalls running PAN-OS software.

* **Nuclei Template:** [🔗 CVE-2025-0107.yaml](https://github.com/packetinside/nuclei-templates/blob/main/http/cves/2025/CVE-2025-0107.yaml)
* **Snort2 Rule:** ```
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Palo Alto Networks Expedition - OS Command Injection"; flow:established,to_server; content:"GET"; http_method; content:"/API/regionsDiscovery.php"; nocase; http_uri; content:"master=spark://"; nocase; distance:0; http_uri; pcre:!"/spark:\/\/(10\.|172\.16\.|192\.168\.)[0-9]{1,3}(\.[0-9]{1,3}){3}/"; sid:1000001; rev:1;)    
    ```
* **Snort3 Rule:** ```
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
      msg:"Palo Alto Networks Expedition - OS Command Injection";
      flow:established,to_server;
      http_method;
      content:"GET";
      http_uri;
      content:"/API/regionsDiscovery.php",nocase;
      content:"master=spark://",nocase,distance:0;
      pcre:!"/spark:\/\/(10\.|172\.16\.|192\.168\.)[0-9]{1,3}(\.[0-9]{1,3}){3}/i";
      sid:1000001;
      rev:1;
    )
    ```
---
