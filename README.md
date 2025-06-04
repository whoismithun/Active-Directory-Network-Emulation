# Active Directory Network Attack Simulation for Offensive Security Practice

This repository contains documentation for an Active Directory network simulation designed for offensive security practice. It outlines the setting up of the network structure, details various network attacks performed, and provides corresponding remediation strategies.

## Project Structure

* `README.md`: This file, providing an overview of the project.
* [`attacks.md`](./attacks.md): Details the network attacks demonstrated within the simulated Active Directory environment.
* [`remediations.md`](./remediations.md): Outlines the remediation strategies to mitigate the described attacks.

## Network Topology

The simulated Active Directory environment consists of the following machines:

* **SIMLAB-DC**: A Windows Server 2019 machine acting as the Domain Controller for `SIMLAB.local`. The `Administrator` account has domain administrative privileges.
* **SIMLAB-PC1**: A Windows 10 Enterprise workstation. The `simlabuser1` account is a local administrator on this machine.
* **SIMLAB-PC2**: A Windows 10 Enterprise workstation. The `simlabuser2` account is a local administrator on this machine.

The diagram below illustrates the network setup:

![Active Directory Network Diagram](./image_6e584f.png)

## Attacks Performed

The `attacks.md` file provides in-depth explanations and step-by-step guides for executing the following network attacks in this simulated environment:

* LLMNR and NBT-NS Poisoning
* SMB Relay Attack
* Pass the Password and Pass the Hash Attacks
* Kerberoasting
* Token Impersonation

## Remediations Implemented

The `remediations.md` file details the practical steps and configurations required to remediate the vulnerabilities exploited by the attacks listed above. These remediations aim to strengthen the security posture of an Active Directory environment.

## Purpose

This project serves as a practical hands-on guide for:

* Understanding common Active Directory network attack vectors.
* Practicing offensive security techniques in a controlled environment.
* Learning and implementing effective defensive and remediation measures against these attacks.

Feel free to explore the linked documentation for detailed attack methodologies and remediation steps.
