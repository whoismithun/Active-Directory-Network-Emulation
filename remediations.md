# Active Directory Network Attack Remediations

This document outlines essential remediation strategies for common network-based attacks targeting Active Directory environments. The focus is on practical steps to mitigate the risks associated with techniques such as **LLMNR/NBT-NS poisoning**, **SMB relay**, **Kerberoasting**, **Token Impersonation**, and **Pass-the-Hash attacks**. Implementing these remediations is crucial for strengthening your network's defensive posture and protecting critical Active Directory infrastructure from compromise.

---

## LLMNR and NBT-NS poisoning

### Turning off LLMNR and NBTNS services in the network

* To disable LLMNR, select “**Turn OFF Multicast Name Resolution**” under `Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client` in the Group Policy Editor.
* To disable NBT-NS, navigate to `Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab` and select “**Disable NetBIOS over TCP/IP**”.

### If LLMNR and NBTNS cannot be disabled

* **Network access control** must be implemented in the network.
* A **strong password policy** must be implemented - prevents malicious actors from cracking password hashes.

---

## SMB Relay attack

* **Enable SMB signing on all devices**: completely stops the attack, but may cause performance issues while copying files.
* **Disable NTLM authentication in the network**: authentication will occur through Kerberos, but if Kerberos stops working then the network defaults to using NTLM authentication.
* **Local admin restriction**: by restricting the number of accounts that are local administrators on other systems based on the nature of the systems and the tasks that the account needs to perform, we can restrict this attack by a large margin.

---

## Pass the password and Pass the hash attacks

* **Limit account re-use**: avoid reusing a password across multiple systems. Disable the Guest and administrator account. Follow the **principle of least privilege**.
* **Implement Privilege Access Management**: check in and out of sensitive accounts when needed, also rotates the password of sensitive accounts on check in and check out. This password is strong and harder to crack as it is constantly rotated.

---

## Kerberoasting

* Implement a **strong password policy** wherein passwords are long, complex and not present in common wordlists that are available on online platforms such as breachforums. Additionally, employees should not use their personal information to create passwords.
* Implement the **policy of least privilege**: Do not give unnecessary privileges to service accounts if the accounts don't require them. Service accounts especially should not have privileges equivalent to domain admin and if they do, other security measures have to be taken to protect the account.

---

## Token Impersonation

* Follow the **principle of least privilege**: Restrict which accounts have `SeImpersonatePrivilege`, `SePrimaryTokenPrivilege`, and `SeDebugPrivilege`. These privileges should only be granted to highly trusted processes. `SeImpersonatePrivilege` is commonly granted to service accounts by default.
* **Monitoring and Auditing**: Set up proper logging mechanisms in the network and keep track of suspicious events by their event IDs, especially the event IDs of **4688, 4672, and 4624**.
* **Implement Endpoint Detection and Response solutions**: EDR is capable of detecting the techniques used for stealing and manipulating tokens based on behavioural analysis.
