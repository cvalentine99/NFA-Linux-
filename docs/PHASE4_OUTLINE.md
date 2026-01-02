# NFA-Linux Phase 4: Advanced Protocol Analysis - Task & Research Outline

**Date:** January 2, 2026  
**Phase:** 4 - Advanced Protocol Analysis  
**Status:** Planning

---

## 1. Introduction & Goals

Phase 4 of the NFA-Linux project transitions from foundational data capture and evidence packaging to high-level application protocol analysis. The primary objective is to decode complex, modern protocols to extract granular forensic artifacts, user actions, and application-layer metadata. This phase is critical for moving beyond flow data and into the realm of content and intent analysis.

The two main pillars of this phase are the implementation of parsers for **QUIC/HTTP/3** and the **Server Message Block (SMB)** protocol. These were selected for their increasing prevalence in modern network traffic and their forensic significance.

### Key Goals for Phase 4:

- **Develop a robust QUIC/HTTP/3 parser:** To analyze encrypted, high-performance web traffic and extract metadata and application data where possible.
- **Implement a comprehensive SMB parser:** To monitor file access, transfers, and commands on corporate networks, detecting lateral movement and data exfiltration.
- **Enhance the Parser Engine:** Refactor the existing parser engine to support stateful, multi-stream protocols like HTTP/3 and SMB.
- **Integrate with Intelligence Layer:** Feed extracted artifacts (files, commands, metadata) into the Phase 3 intelligence layer for hashing, timestamping, and CASE/UCO packaging.

---

## 2. Overall Task Breakdown

This phase is divided into several key development and research streams:

| Task ID | Task Name | Description | Priority | Estimated Effort |
| :--- | :--- | :--- | :--- | :--- |
| **4.1** | **QUIC/HTTP/3 Parser Implementation** | Build the complete parsing and analysis stack for QUIC and HTTP/3 traffic. | High | 15-20 days |
| **4.2** | **SMBv2/v3 Parser Implementation** | Build the parsing engine for modern SMB dialects to track file operations. | High | 12-18 days |
| **4.3** | **Parser Engine Refactoring** | Update the core parser engine to handle connection-oriented, stateful protocols. | Medium | 5-7 days |
| **4.4** | **Integration with Intelligence Layer** | Connect the new parsers to the file carving, integrity, and evidence packaging modules. | Medium | 4-6 days |
| **4.5** | **Unit & Integration Testing** | Develop comprehensive tests using captured PCAP files for all new parsers. | High | 8-10 days |

This document will now detail the specific tasks and research required for the two main implementation efforts: **QUIC/HTTP/3** and **SMB**.


---

## 3. Task 4.1: QUIC/HTTP/3 Parser Implementation

QUIC and its application protocol, HTTP/3, represent the future of web traffic. Their encrypted-by-default nature presents significant challenges for passive network analysis. The goal is not to break encryption, but to extract the maximum amount of forensic metadata from the unencrypted portions of the protocol and to lay the groundwork for decryption where keys are available.

### 3.1. Implementation Tasks

| Task ID | Sub-Task | Description | Key Challenges |
| :--- | :--- | :--- | :--- |
| 4.1.1 | QUIC Packet Parsing | Implement a parser for QUIC packet headers (Long and Short headers). This includes parsing Initial, 0-RTT, Handshake, and 1-RTT packets. The parser must correctly extract Source and Destination Connection IDs (SCID/DCID) and handle version negotiation. | Packet header format variations; connection ID correlation across packets. |
| 4.1.2 | TLS 1.3 Metadata Extraction | From the QUIC Initial and Handshake packets, extract unencrypted TLS 1.3 ClientHello and ServerHello metadata. This includes the Server Name Indication (SNI), Application-Layer Protocol Negotiation (ALPN), and any available certificate information. | Parsing TLS records from within QUIC frames; handling TLS extensions. |
| 4.1.3 | QUIC & HTTP/3 Fingerprinting | Implement JA4+ fingerprinting techniques for QUIC traffic. This involves creating a hash from specific fields in the TLS ClientHello. Research and implement additional fingerprinting methods based on QPACK settings or HTTP/3 SETTINGS frames. | Accurately identifying and ordering the correct fields for the JA4+ hash; developing novel fingerprints for HTTP/3. |
| 4.1.4 | QUIC Stream Reassembly | Develop a stateful reassembly engine for QUIC streams. This engine must manage multiple bidirectional and unidirectional streams within a single QUIC connection, handling stream-level flow control and ordering. | High memory usage; managing the state of thousands of concurrent streams per connection. |
| 4.1.5 | HTTP/3 Frame & QPACK Parsing | On reassembled QUIC streams, parse HTTP/3 frames (DATA, HEADERS, SETTINGS, etc.). A critical sub-task is implementing a QPACK parser to decompress HTTP headers, which requires maintaining a stateful dynamic table for each connection. | QPACK's stateful nature makes it complex to parse passively; handling dynamic table updates correctly is crucial for header reconstruction. |
| 4.1.6 | Data Model Integration | Create new data structures (`models.QUICConnection`, `models.HTTP3Request`) to store extracted information. This includes connection details, stream data, HTTP/3 headers, URLs, and fingerprints. | Designing a schema that efficiently links QUIC connections to their underlying UDP flows and contained HTTP/3 transactions. |

### 3.2. Required Research

| Research ID | Topic | Description | Key Questions & Goals |
| :--- | :--- | :--- | :--- |
| 4.1.A | Go Libraries for QUIC/HTTP/3 | Investigate existing Go libraries for parsing and handling QUIC and HTTP/3. The primary candidate is `quic-go`, but its suitability for passive analysis must be determined. | Can `quic-go` be used for passive, off-the-wire parsing, or is it only for client/server implementations? Are there lower-level libraries for parsing QUIC packets and HTTP/3 frames? What libraries exist for QPACK? |
| 4.1.B | QUIC Decryption Methods | Research the mechanisms for decrypting QUIC traffic when session keys are available. This involves understanding how to use an `SSLKEYLOGFILE` (as generated by browsers) to derive the specific traffic secrets for a QUIC connection. | What are the exact steps to derive QUIC `client_traffic_secret_0`, `server_traffic_secret_0`, and subsequent keys from the master secret? How does this differ from TLS 1.2? |
| 4.1.C | Advanced QUIC Fingerprinting | Go beyond JA4+ to identify other potential fingerprinting surfaces in QUIC and HTTP/3. This could include the order and values of transport parameters, the pattern of frame types in a SETTINGS frame, or characteristics of the QPACK dynamic table. | What parts of the QUIC and HTTP/3 handshakes are both unencrypted and variable enough to serve as a reliable fingerprint? Can machine learning be applied to packet size and timing to classify encrypted QUIC sessions? |
| 4.1.D | Relevant RFCs & Standards | A thorough review of the core RFCs is mandatory for a correct and robust implementation. | - **RFC 9000:** QUIC Transport Protocol\n- **RFC 9001:** Using TLS to Secure QUIC\n- **RFC 9114:** HTTP/3\n- **RFC 9204:** QPACK: Field Compression for HTTP/3 |


---

## 4. Task 4.2: SMBv2/v3 Parser Implementation

The Server Message Block (SMB) protocol is ubiquitous in Windows-based enterprise environments, making it a high-value target for forensic analysis. Monitoring SMB traffic can reveal unauthorized file access, data exfiltration, lateral movement by attackers, and the deployment of malware or ransomware. This task focuses on parsing modern SMB dialects (SMBv2 and SMBv3) to reconstruct file operations and administrative commands.

### 4.1. Implementation Tasks

| Task ID | Sub-Task | Description | Key Challenges |
| :--- | :--- | :--- | :--- |
| 4.2.1 | SMB2/3 Header & Transport | Implement a parser for the NetBIOS Session Service (NBSS) and the SMB2/3 header. This includes handling packet defragmentation over TCP and correctly identifying the start of an SMB message. The parser must extract the Command, SessionID, and TreeID fields. | SMB messages can be split across multiple TCP packets; correctly reassembling them before parsing is critical. |
| 4.2.2 | Session & Tree State Management | Create a state machine to track SMB sessions and tree connections. This involves parsing `SessionSetup` and `TreeConnect` request/response pairs to link a `SessionID` and `TreeID` to a specific user and network share (e.g., `\\\\SERVER\\C$`). | Managing the lifecycle of sessions and trees, including handling logoffs and disconnects, to avoid memory leaks. |
| 4.2.3 | File Operation Parsing | Parse the most common file operation commands: `CREATE` (to get filenames), `READ`, `WRITE`, `SET_INFO` (for renames), and `CLOSE`. The goal is to reconstruct a timeline of file access and identify data being transferred. | Correlating separate `READ` and `WRITE` commands to the same file handle; triggering the file carving engine on `WRITE` command data. |
| 4.2.4 | Lateral Movement Command Parsing | Implement parsers for commands frequently used in lateral movement. This includes `IOCTL` requests (especially those targeting the Service Control Manager) and `CREATE` requests to administrative shares like `ADMIN$` and `IPC$`. | The `IOCTL` command is a generic container; parsing its various sub-commands requires deep protocol knowledge. Identifying the specific patterns of tools like PsExec. |
| 4.2.5 | File Transfer Extraction | For `READ` and `WRITE` commands, extract the file data from the SMB message body. This data will be passed to the Phase 3 file carving and intelligence engine to identify the file type, compute its hash, and store it as evidence. | Handling large file transfers that are chunked across many SMB messages; reassembling these chunks in the correct order. |
| 4.2.6 | Data Model Integration | Design and implement new data structures (`models.SMBSession`, `models.SMBFileOperation`) to store parsed SMB data. This includes user, share, filename, operation type, and status. | Creating a relational model that links a user to a session, a session to a tree, and a tree to multiple file operations. |

### 4.2. Required Research

| Research ID | Topic | Description | Key Questions & Goals |
| :--- | :--- | :--- | :--- |
| 4.2.A | Go Libraries for SMB Parsing | Survey existing Go libraries for parsing SMB. Candidates include `gopacket/layers` (for basic SMB1/2), `go-smb`, and potentially others. The goal is to find a library that can handle the complexity of SMBv2/3 command structures. | How complete are the SMBv2/3 dissectors in `gopacket`? Can `go-smb` be adapted for passive parsing, or is it client-only? Is it more feasible to write a custom parser from scratch using the official specifications? |
| 4.2.B | SMBv3 Encryption | Research the handshake and mechanisms for SMBv3 encryption. While decryption is out of scope, the parser must be able to identify an encrypted session, log it, and extract any available unencrypted metadata (e.g., the `TreeConnect` to the share). | How is SMBv3 encryption negotiated in the `SessionSetup` response? What metadata remains visible after the session is encrypted? Can we still track which user is connected to which share? |
| 4.2.C | Attacker Lateral Movement via SMB | Study and document common attacker techniques that leverage SMB. This includes the use of tools like PsExec, Cobalt Strike's SMB beacon, and credential dumping via administrative shares. | What is the exact sequence of SMB commands used by PsExec to upload and execute a service binary? How does an SMB beaconing implant behave differently from normal user traffic? What are the indicators of DCSync attacks over SMB? |
| 4.2.D | Relevant RFCs & Standards | The primary source of truth for SMB is the official Microsoft documentation. A thorough review is essential. | - **[MS-SMB2]:** Server Message Block (SMB) Protocol Versions 2 and 3\n- **[MS-NBTE]:** NetBIOS over TCP/IP (for transport)\n- **[MS-RPCE]:** Remote Procedure Call Protocol Extensions (for understanding `IOCTL` commands) |


---

## 5. Conclusion

Phase 4 represents a significant leap in the analytical capabilities of NFA-Linux. By successfully implementing parsers for QUIC/HTTP/3 and SMBv2/v3, the platform will gain deep visibility into both modern encrypted web traffic and internal corporate network activities. The research and implementation tasks outlined above provide a clear roadmap for this development. The key to success will be a thorough understanding of the protocol specifications and a robust, stateful parsing architecture.

Upon completion of this phase, NFA-Linux will be equipped to extract high-value forensic artifacts that are currently opaque to many commercial tools, solidifying its position as a next-generation network forensics platform.

---

## 6. References

- **[1]** IETF RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport. [https://www.rfc-editor.org/rfc/rfc9000.html](https://www.rfc-editor.org/rfc/rfc9000.html)
- **[2]** IETF RFC 9001: Using TLS to Secure QUIC. [https://www.rfc-editor.org/rfc/rfc9001.html](https://www.rfc-editor.org/rfc/rfc9001.html)
- **[3]** IETF RFC 9114: HTTP/3. [https://www.rfc-editor.org/rfc/rfc9114.html](https://www.rfc-editor.org/rfc/rfc9114.html)
- **[4]** IETF RFC 9204: QPACK: Field Compression for HTTP/3. [https://www.rfc-editor.org/rfc/rfc9204.html](https://www.rfc-editor.org/rfc/rfc9204.html)
- **[5]** Microsoft Docs [MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3. [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ac37-5ee3-43ca-8ff5-70125338d447](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ac37-5ee3-43ca-8ff5-70125338d447)
- **[6]** Microsoft Docs [MS-NBTE]: NetBIOS over TCP/IP (NBTE) Protocol. [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/b183d71a-6963-4399-9674-3d1641544391](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/b183d71a-6963-4399-9674-3d1641544391)
- **[7]** Microsoft Docs [MS-RPCE]: Remote Procedure Call Protocol Extensions. [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/292825c6-3e35-4a0a-a537-23ea41c8af28](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/292825c6-3e35-4a0a-a537-23ea41c8af28)
