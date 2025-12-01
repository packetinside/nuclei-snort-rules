---
layout: default
title: Home
---

# 🛡️ Nuclei 공격 탐지 Snort Rules 아카이브

<table>
  <thead>
    <tr>
      <th style="width: 15%">CVE ID</th>
      <th style="width: 35%">Title</th>
      <th style="width: 15%">Nuclei</th>
      <th style="width: 15%">Pcap</th>
      <th style="width: 20%">Snort Rule</th>
    </tr>
  </thead>
  <tbody>
    {% for cve in site.cves %}
    <tr>
      <td style="font-weight:bold; color:#d9534f;">{{ cve.cve_id }}</td>

      <td>
        <a href="{{ cve.url | relative_url }}" style="text-decoration: none; color: #0366d6;">
          {{ cve.title }}
        </a>
      </td>

      <td style="text-align: center;">
        {% if cve.nuclei_url %}
        <a href="{{ cve.nuclei_url }}" target="_blank">🔗 Template</a>
        {% else %}
        -
        {% endif %}
      </td>

      <td style="text-align: center;">
        <a href="{{ '/pcaps/' | append: cve.slug | append: '.pcap' | relative_url }}" download style="text-decoration: none;" title="Download PCAP">
          🦈 Download
        </a>
      </td>

      <td style="text-align: center;">
        <a href="{{ cve.url | relative_url }}#snort-rules" style="background-color: #f6f8fa; padding: 4px 8px; border: 1px solid #d1d5da; border-radius: 3px; text-decoration: none; font-size: 0.85em; color: #24292e;">
          📜 View Rules
        </a>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
