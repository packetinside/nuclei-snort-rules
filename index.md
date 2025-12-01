---
layout: default
title: Database
---

<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; width: 100%;">
    
    <h2 style="margin: 0; border: none; font-size: 1.5em; color: #343a40; font-weight: 700;">
        <i class="fas fa-database" style="color: #d9534f; margin-right: 8px;"></i> Vulnerabilities
    </h2>
    
    <div style="position: relative; width: 250px;">
        <i class="fas fa-search" style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: #adb5bd; font-size: 0.9em;"></i>
        
        <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search CVE, Title..." 
               style="width: 100%; padding: 10px 10px 10px 35px; border: 1px solid #ced4da; border-radius: 5px; font-size: 0.9em; box-sizing: border-box; outline: none; transition: 0.2s;">
    </div>
</div>

<table id="vulnTable">
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

<div id="noResults" style="display: none; text-align: center; padding: 40px; color: #6c757d; background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">
    <p style="margin:0;"><i class="fas fa-exclamation-circle"></i> No matching records found.</p>
</div>

<script>
function filterTable() {
  var input = document.getElementById("searchInput");
  var filter = input.value.toUpperCase();
  var table = document.getElementById("vulnTable");
  var tr = table.getElementsByTagName("tr");
  var hasResult = false;

  // 헤더(0번째 줄)는 건너뛰고 1번째 줄부터 반복
  for (var i = 1; i < tr.length; i++) {
    var tdId = tr[i].getElementsByTagName("td")[0];     // CVE ID
    var tdTitle = tr[i].getElementsByTagName("td")[1];  // Title
    
    if (tdId || tdTitle) {
      var txtId = tdId.textContent || tdId.innerText;
      var txtTitle = tdTitle.textContent || tdTitle.innerText;
      
      // 검색어가 포함되어 있으면 표시
      if (txtId.toUpperCase().indexOf(filter) > -1 || txtTitle.toUpperCase().indexOf(filter) > -1) {
        tr[i].style.display = "";
        hasResult = true;
      } else {
        tr[i].style.display = "none";
      }
    }       
  }
  
  // 결과 없음 메시지 표시/숨김
  document.getElementById("noResults").style.display = hasResult ? "none" : "block";
}
</script>
