### Tripwire: Proof of Concept 

By Ramyar Daneshgar

#### **Overview**
Tripwire is a proof of concept for **Host Intrusion Detection System (HIDS)** designed to monitor file integrity in real-time. By leveraging **event-driven detection** and **SHA-256 hashing**, the system identifies unauthorized file modifications, additions, and deletions, providing immediate desktop alerts and maintaining comprehensive event logs for forensic analysis.

---

### **Key Features**
1. **Real-Time File Integrity Monitoring**:
   - Implements continuous monitoring using the **Watchdog** library to track unauthorized file system events.
   - Detects critical file activities, including:
     - **File Modifications**: Unauthorized changes to file contents.
     - **File Additions**: Detection of newly created files in sensitive directories.
     - **File Deletions**: Identification of removed or tampered files.

2. **Alerting and Notifications**:
   - Utilizes **Plyer** for immediate desktop notifications upon detection of suspicious file events.
   - Alerts include the event type (e.g., modification, deletion) and file path to enable rapid response.

3. **File Integrity Validation**:
   - Hashes file contents using **SHA-256** to ensure cryptographic integrity.
   - Compares current file states with a secure baseline stored in `baseline.json` to identify anomalies.

4. **Audit and Logging**:
   - Maintains a timestamped log of all events in `tripwire_log.txt` to support **incident response** and **forensic investigations**.

---

### **How It Works**
1. **Initialization**:
   - Automatically sets up a monitoring directory (`./monitor`) if it doesn’t exist.
   - Generates a secure baseline by hashing existing files in the directory.

2. **Event Detection**:
   - Monitors the directory in real-time, leveraging **file system event hooks** to detect activity.
   - Logs and notifies on critical events such as unauthorized file changes, creations, and deletions.

3. **Periodic File Integrity Checks**:
   - Regularly compares the directory’s file hashes against the stored baseline to detect tampering.

4. **Notifications and Logs**:
   - Issues desktop alerts for each detected event:
     ```
     Tripwire Alert
     Modified File: ./monitor/example.txt
     ```
   - Logs all activities for review:
     ```
     [2025-01-02 14:35:10] New File: ./monitor/example.txt
     [2025-01-02 14:36:15] Modified File: ./monitor/example.txt
     [2025-01-02 14:38:00] Deleted File: ./monitor/example.txt
     ```

---

### **Cybersecurity Implications**
1. **Threat Detection**:
   - Acts as a proactive **HIDS** mechanism to detect file tampering or intrusion attempts.

2. **File Integrity Assurance**:
   - Provides cryptographic validation of sensitive files, ensuring their integrity.

3. **Incident Response**:
   - Logs and notifications assist in rapid triaging and containment of security incidents.

4. **Forensics**:
   - Timestamps and detailed logs support post-incident analysis and evidence collection.

5. **Access Monitoring**:
   - Highlights unauthorized file access or changes, reducing the risk of insider threats.
