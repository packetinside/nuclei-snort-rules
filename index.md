---
layout: default
title: Database
---

<div style="margin-bottom: 20px;">
    <h2 style="margin: 0; border: none; font-size: 1.5em; color: #343a40; font-weight: 700;">
        <i class="fas fa-database" style="color: #d9534f; margin-right: 8px;"></i> Snort Rule Database
    </h2>
</div>

<table id="vulnTable" class="display" style="width:100%">
  <thead>
    <tr>
      <th style="width: 15%">CVE ID</th>
      <th style="width: 35%">Title</th>
      <th style="width: 15%; text-align: center;">Nuclei</th>
      <th style="width: 15%; text-align: center;">Pcap</th>
      <th style="width: 20%; text-align: center;">Snort Rule</th>
    </tr>
  </thead>
  <tbody>
    {% for cve in site.cves %}
    <tr>
      <td style="font-weight:bold; color:#d9534f; font-family: monospace;">{{ cve.cve_id }}</td>

      <td>
        <a href="{{ cve.url | relative_url }}#info" style="font-weight: 500;">
          {{ cve.title }}
        </a>
      </td>

      <td style="text-align: center;">
        {% if cve.nuclei_url %}
        <a href="{{ cve.nuclei_url }}" target="_blank" style="color: #28a745; font-size: 0.9em;">
            <i class="fas fa-file-code"></i> Template
        </a>
        {% else %}
        <span style="color: #ccc;">-</span>
        {% endif %}
      </td>

      <td style="text-align: center;">
        <a href="{{ '/pcaps/' | append: cve.slug | append: '.pcap' | relative_url }}" download style="color: #17a2b8; font-size: 0.9em;" title="Download PCAP">
          <i class="fas fa-download"></i> PCAP
        </a>
      </td>

      <td style="text-align: center;">
        <a href="{{ cve.url | relative_url }}#rules" style="background-color: #fff; border: 1px solid #dee2e6; color: #495057; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; display: inline-block;">
          <i class="fas fa-eye"></i> View Rules
        </a>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<script>
    $(document).ready(function() {
        $('#vulnTable').DataTable({
            // 1. 기본 정렬: 첫 번째 컬럼(CVE ID)을 기준으로 내림차순(최신순) 정렬
            "order": [[ 0, "desc" ]],
            
            // 2. 페이지당 보여줄 개수 설정
            "pageLength": 15,
            "lengthMenu": [[15, 30, 50, 100, -1], [15, 30, 50, 100, "All"]],
            
            // 3. 검색, 페이징, 정보 표시 활성화
            "searching": true,
            "paging": true,
            "info": true,
            
            // 4. 언어 설정 (영문)
            "language": {
                "search": "_INPUT_",
                "searchPlaceholder": "Search CVE, Title...",
                "lengthMenu": "Show _MENU_ entries",
                "info": "Showing _START_ to _END_ of _TOTAL_ vulnerabilities"
            }
        });
    });
</script>
