# HideSAMDump

Windows introduced **Alternate Data Streams (ADS)** with the adoption of the NTFS file system. ADS allows files and directories to contain additional hidden data streams that are not visible through standard file listing operations.

## C: Drive Peculiarity

The [CrowdStrike analysis of the ALPHA SPIDER ransomware attack](https://www.crowdstrike.com/en-us/blog/anatomy-of-alpha-spider-ransomware/?utm_source=chatgpt.com) documented the use of ADS to establish persistence on compromised systems. Specifically, the threat actors deployed an executable and concealed it within an Alternate Data Stream attached to the root directory of the **C:** volume.

As noted in the report:

*"Many tools — including the system `dir` command and common PowerShell cmdlets — would not show an ADS on the root volume, even though these commands would display ADSs on other files and directories."*

This behavior makes ADS attached to the root of the system drive particularly attractive for stealthy persistence and data storage techniques.

---
**Remarks:** Among the administrative tools I have tested, the only utility that reliably enumerates ADS attached to the root directory of the **C:** drive is [Streams (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/streams).
---

## My Use Case

I developed a small PE that exports the **SAM**, **SYSTEM**, and **SECURITY** registry hives and stores the resulting data in separate Alternate Data Streams attached to the root directory of the **C:** drive.

This approach places the dumps at the root of the file system while leveraging a location that remains invisible to standard user workflows and many administrative inspection tools. As a result, the files are less likely to be discovered during routine system examination.

