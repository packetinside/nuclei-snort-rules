---
layout: default
title: Database
---

<div style="margin-bottom: 20px;">
    <h2 style="margin: 0; border: none; font-size: 1.5em; color: #343a40; font-weight: 700;">
        <i class="fas fa-database" style="color: #d9534f; margin-right: 8px;"></i> Vulnerabilities Database
    </h2>
</div>

<table id="vulnTable" class="display" style="width:100%">
  <thead>
    <tr>
      <th style="width: 10%">CVE ID</th>
      <th style="width: 46%">TITLE</th>
      <th style="width: 12%; text-align: center;">Nuclei</th>
      <th style="width: 12%; text-align: center;">PCAP</th>
      <th style="width: 20%; text-align: center;">Snort Rule</th>
    </tr>
  </thead>
  <tbody>
    {% for cve in site.cves %}
    <tr>
      <td style="font-weight:bold; color: #5f6368; font-family: monospace; font-size: 0.8em;">{{ cve.cve_id }}</td>

      <td>
        <a href="{{ cve.url | relative_url }}#info" style="font-weight: 500; color: #0d233a; font-size: 0.9em;">
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
        {% if cve.pcap %}
        <a href="{{ cve.pcap_path | relative_url }}" download style="color: #17a2b8; font-size: 0.9em;" title="Download PCAP">
          <i class="fas fa-download"></i> PCAP
        </a>
        {% else %}
        <span style="color: #ccc;">-</span>
        {% endif %}
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
            "order": [[ 0, "desc" ]],
            "pageLength": 15,
            "lengthMenu": [[15, 30, 50, 100, -1], [15, 30, 50, 100, "All"]],
            "searching": true,
            "paging": true,
            "info": true,
            "language": {
                "search": "_INPUT_",
                "searchPlaceholder": "Search CVE, Title...",
                "lengthMenu": "Show _MENU_ entries",
                "info": "Showing _START_ to _END_ of _TOTAL_ vulnerabilities"
            }
        });
    });
</script>
