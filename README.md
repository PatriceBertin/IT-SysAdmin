---
# **A Week in the Life of a System Administrator at BMW Berlin (300+ Users)**  


---

## **📅 Day 1: Monday – System Health, Patch Management & User Onboarding**  
**⏰ Time: 7:00 AM – 12:00 PM**  

### **🔹 7:00 AM – System Health Check**  
**Tools Used:**  
- **Nagios/Icinga** (Infrastructure monitoring)  
- **Zabbix** (Performance tracking)  
- **Linux CLI (`top`, `df -h`, `netstat`)**  

**Steps:**  
1. Log into Nagios dashboard to check for **critical alerts** (server down, high CPU, disk full).  
2. Verify **Zabbix triggers** for abnormal memory usage trends.  
3. Manually inspect key servers:  
   - `top` → Identify runaway processes.  
   - `df -h` → Check `/var` and `/home` partitions.  
   - `netstat -tuln` → Look for unexpected open ports.  

**Findings:**  
- **One server (fileserver01) had 95% disk usage** → Logs not rotating properly.  
- **High CPU on a database server** → MySQL query optimization needed.  

- **Cleared old logs** with `logrotate -f /etc/logrotate.conf`.  
- **Scheduled MySQL slow query log analysis** for later.  
**Resolution:**  

**Goal:**  

---

✅ Ensure all critical systems are operational before business hours.  
### **🔹 8:00 AM – Patch Management**  
- **Ansible (Linux)**  
**Tools Used:**  
- **WSUS (Windows)**  

- **PowerShell (Windows updates)**  
**Steps:**  
   ```bash
   # Dry-run first
1. **Linux (Debian/Ubuntu):**  
   ansible-playbook patch_servers.yml --check
   # Apply patches
   ```
   - Playbook ensures **reboots happen in batches** to avoid downtime.  
   ansible-playbook patch_servers.yml

2. **Windows:**  
   ```powershell
   # Check pending updates
   Get-WindowsUpdate -MicrosoftUpdate
   # Install critical patches
   Install-WindowsUpdate -AcceptAll -AutoReboot
   ```
   - **WSUS** approves patches after testing.  

**Findings:**  
- **One legacy app broke after .NET update** → Rolled back via `wusa /uninstall /kb:5005565`.  
- **Linux kernel update required reboot** → Scheduled for maintenance window.  

**Goal:**  
✅ Keep systems secure with minimal disruption.  

---

### **🔸 10:00 AM – New Hire Onboarding**  
**Tools Used:**  
- **Active Directory (PowerShell)**  
- **Microsoft Intune (MDM)**  
- **ServiceNow (Ticket tracking)**  

**Steps:**  
1. **Create AD Account:**  
   ```powershell
   New-ADUser -Name "Anna Schmidt" -SamAccountName "aschmidt" -Enabled $true -Password (ConvertTo-SecureString "Temp@Pass2024!" -AsPlainText -Force)
   ```
2. **Assign Groups & Permissions:**  
   ```powershell
   Add-ADGroupMember -Identity "BMW_Engineering" -Members "aschmidt"
   ```
3. **Deploy Laptop via Intune:**  
   - Pre-staged Autopilot profile.  
   - Verified software (SolidWorks, VPN, Office) installed automatically.  

**Findings:**  
- **User couldn’t access SAP** → Missing role assignment in SAP GUI.  
- **Fixed by adding her to the correct AD group synced to SAP.**  

**Goal:**  
✅ New hire fully operational by EOD.  

---

## **📅 Day 2: Tuesday – Network Security & Vulnerability Scan**  
**⏰ Time: 8:00 AM – 5:00 PM**  

### **🔹 8:00 AM – Firewall Audit**  
**Tools Used:**  
- **Palo Alto Panorama**  
- **Wireshark/tcpdump**  

**Steps:**  
1. Reviewed **last 30 days of firewall logs** for:  
   - Unused NAT rules.  
   - Suspicious geo-IP traffic (e.g., Russia, China).  
2. **Blocked high-risk IPs:**  
   ```bash
   iptables -A INPUT -s 45.155.205.0/24 -j DROP
   ```
3. **Packet capture for investigation:**  
   ```bash
   tcpdump -i eth0 'port 3389' -w /tmp/rdp_traffic.pcap
   ```

**Findings:**  
- **An outdated rule allowed RDP from the internet** → Disabled immediately.  
- **Brute-force attempts on VPN** → Enabled MFA enforcement.  

**Goal:**  
✅ Reduce attack surface by 20%.  

---

### **🔸 11:00 AM – Vulnerability Scan**  
**Tools Used:**  
- **Nessus**  
- **OpenVAS**  

**Steps:**  
1. Ran **credentialed scan** on all servers:  
   ```bash
   nessuscli scan --policy "BMW_High_Risk" --targets 10.10.1.0/24
   ```

**Findings:**  
- **Apache 2.4.49 (CVE-2021-41773)** → Upgraded to 2.4.58.  
- **Windows Server 2012 R2 (EOL)** → Scheduled migration to 2022.  

**Goal:**  
✅ Patch critical vulnerabilities within 48 hours.  

---

### **🔹 2:00 PM – VPN Troubleshooting**  
**Tools Used:**  
- **Cisco AnyConnect logs**  
- **Cisco ISE**  

**Steps:**  
1. User reported **"SSL Handshake Failed"** error.  
2. Checked logs:  
   ```bash
   grep "TLS Error" /var/log/anyconnect.log
   ```
3. **Root cause:** Outdated certificate.  
4. **Fixed by renewing cert in ISE and pushing new profile.**  

**Goal:**  
✅ Restore secure remote access.  

---

## **📅 Day 3: Wednesday – Backup & Disaster Recovery**  
**⏰ Time: 9:00 AM – 4:00 PM**  

### **🔹 9:00 AM – Backup Verification**  
**Tools Used:**  
- **Veeam Backup & Replication**  
- **PowerShell (for restore tests)**  

**Steps:**  
1. **Checked backup jobs in Veeam console** → Last night’s job succeeded.  
2. **Tested restore of a critical VM:**  
   ```powershell
   Start-VBRRestoreVM -Job "Nightly_Backup" -VM "BMW-SQL01"
   ```
3. **Validated SQL databases** were uncorrupted.  

**Findings:**  
- **Backup took 30% longer** due to new 500GB CAD files.  
- **Adjusted backup window** to avoid conflicts.  

2. Exported findings to CSV and **prioritized CVSS 9.0+ issues**.  
**Goal:**  
✅ Ensure RTO < 2 hours for critical systems.  

---
### **🔸 12:00 PM – Storage Expansion**  
**Tools Used:**  
- **LVM (Linux)**  
- **Diskpart (Windows)**  

**Steps:**  
1. **Added 100GB SAN storage to VMware.**  
2. **Extended Linux volume:**  
   ```bash
   lvextend -L +100G /dev/vg_data/lv_home
   resize2fs /dev/vg_data/lv_home
   ```
3. **Windows Server:**  
   ```powershell
   diskpart
   select volume 2
   extend
   ```

**Goal:**  
✅ Prevent user downtime from full disks.  

## **📅 Day 4: Thursday – Automation & Scripting**  

**⏰ Time: 8:00 AM – 3:00 PM**  

- **Python + Cron**  
### **🔹 8:00 AM – Log Cleanup Automation**  
**Tools Used:**  

**Script:**  
```python
import os, glob, datetime
        os.rename(log, f"/archive/logs/{os.path.basename(log)}")
for log in glob.glob("/var/log/*.log"):
    if (datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(log)) > datetime.timedelta(days=30)):
```
**Deployed via Cron:**  
```bash
```


**Goal:**  
✅ Save 5 hours/month of manual cleanup.  

---


## **📅 Day 5: Friday – User Support & Documentation**  
**⏰ Time: 8:00 AM – 2:00 PM**  

### **Tasks:**  
1. **🔹 8:00 AM – Password Resets (5+ tickets)**  
   - Used **AD PowerShell**:  
     ```powershell
     Set-ADAccountPassword -Identity "jdoe" -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)
     ```  

2. **🔸 12:00 PM – Update IT Wiki (Confluence)**  
   - Added **new troubleshooting guides**.  

### **Findings & Goals:**  
✅ **Success:** Reduced repeat tickets with better docs.  

---

## **📅 Day 6: Saturday – On-Call Emergency**  
**⏰ Time: (After-hours – 10:00 PM)**  

### **Tasks:**  
1. **🔹 10:00 PM – Database Server Crash**  
   - MySQL crashed due to full disk.  
   - **Actions Taken:**  
     - Freed space by clearing old logs.  
     - Restarted service:  
       ```bash
       systemctl restart mysql
       ```  

### **Findings & Goals:**  
⚠️ **Issue:** Need better disk monitoring.  

---

## **📅 Day 7: Sunday – Proactive Monitoring Tuning**  
**⏰ Time: 1:00 PM – 3:00 PM**  

### **Tasks:**  
1. **🔹 1:00 PM – Adjust Zabbix Alerts**  
   - Lowered CPU warning threshold from **90% → 80%**.  

### **Findings & Goals:**  
✅ **Success:** Early warnings prevent future outages.  

---

## **🛠️ Tools & Scripts Used**  
| **Category**       | **Tools/Scripts**                          |  
|--------------------|-------------------------------------------|  
| **Monitoring**     | Nagios, Zabbix, Grafana                   |  
| **Automation**     | Ansible, PowerShell, Python               |  
| **Backup**         | Veeam, rsync                              |  
| **Security**       | Nessus, FortiGate, Cisco AnyConnect       |  
| **User Management**| Active Directory, Microsoft Intune        |  

---


## **🔑 Key Results & Metrics**  
| **Task**               | **Improvement**                     |  
|------------------------|-------------------------------------|  
| Patching               | 100% compliance in 7 days           |  
| Backup Reliability     | 99.99% success rate                 |  
| Ticket Resolution      | 30% faster with automation          |  




0 2 * * * /usr/bin/python3 /scripts/log_cleaner.py
