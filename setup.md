# AD project

structure of the Active Directory Network
![structure](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/AD_lab%20setup.png)

## VMs

1.  1 windows server 2019 VM
2.  2 windows 10 enterprise VMs
3.  1 Kali linux VM

## minimum requirements

-   60 GB disk space
-   16 GB RAM

steps to setup

-   visit [microsoft evaluation center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019) website and install the 64 bit version of the windows server 2019 iso file
-   visit the [microsoft evaluation center](https://www.microsoft.com/en-in/evalcenter/evaluate-windows-10-enterprise) website and install the 64 bit version of the windows 10 enterprise edition iso file
-   visit the official [get kali page](https://www.kali.org/get-kali/#kali-virtual-machines) of Offsec to download the Kali linux VM

## Domain controller setup

1.  click create new VM in vmware and select the windows server 2019 iso file filename consists of SERVER_EVAL
2.  when the new virtual machine wizard says windows server 2019 click detected click next
3.  choose windows server 2019 standard for the version of windows to install and click next, click yes if a prompt for product key appears
4.  choose location to store VM and click next
5.  set maximum disk size (GB) to 60 and choose split virtual disk into multiple files, then click next
6.  uncheck power on this virtual machine option and click finish
![server2019_specs](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/server2019_specs.jpg)
7.  click edit virtual machine settings and remove the floppy drive setting to ensure no incompatibility when it prompts for a key
8.  choose bridged in the network connection setting in the network adapter section
9.  choose 4 GB of RAM in the memory section and change this setting to 2 GB after the completion of the setup process to ensure smooth setup
10. click play virtual machine and click the VM screen - press any key when prompted to press for any key
11. in the language settings section leave the default settings on and click next
12. click install now
13. select windows server 2019 standard desktop evaluation(Desktop experience) for the operating system you want to install and click next
14. click “i accept the license terms” and click next
15. click custom install for the type of installation and click next
16. we see that there exists a drive 0 unallocated space of 60 gb, click new and then click apply - click OK and click next
17. after the installation is complete, we are shown the customize settings page, here set the password for the administrator account as P@$$w0rd! or any other easy to remember password, re enter the password and click finish
![DC_password](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/DC_password.jpg)
18. send ctrl+alt+del from the vmware taskbar and login to the system with administrator account and the password that you just set
![DC_login](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/DC_login.jpg)
19. in the VMware taskbar go to manage and click install vmware tools then click install in the popup that appears
20. click the dvd drive (D:) vmware tools popup that appears on the VM screen and click run setup64.exe
21. click next in the vmware tools setup wizard, then click complete install for the setup type, click next and finally click install
22. click finish and then click no for the restart now prompt because we still have a few more settings to configure before restarting
23. click view your PC name after searching for computer in the windows searchbar
24. in this section click on rename your PC and give it an appropriate name like “SIMLAB-DC” and click next
![DC_naming](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/DC_naming.jpg)
25. click restart now, choose other(unplanned) and click continue
26. after the restart is complete login to the system with your credentials, and the server manager application opens on its own
27. we will now proceed to install a domain controller on this system, click manage and select add roles and features
28. click next for before you begin, select role based or feature based installation for installation type and click next, leave defaults for server selection and click next, under server roles, click active directory domain services or AD DS click on add features and click next , leave the rest of the settings to default and under results click install
![setting_up_AD_DS](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/setting_up_AD_DS.jpg)
29. after installation is complete, click close. After we click close, we see an exclamation sign in the flag icon next to the manage button, click the flag and click promote this server to a domain controller
30. under deployment configuration select add a new forest option for the select the deployment operation and give an appropriate Root Domain name like “SIMLAB.local”
![domain_naming](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/domain_naming.jpg)
31. under the domain controller options, enter an appropriate DSRM password, we can just give the same P@$$w0rd! as the password and click next
32. leave the other settings to default and click install under prerequisites check - this will reboot the machine, when we login to the machine we see that we are logging into the system on the SIMLAB domain as the prompt is for the SIMLAB\Administrator account
![finishing_domain_setup](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/finishing_domain_setup.jpg)


## windows 10 enterprise machines setup

1.  click on create a new virtual machine, for the iso click browse and select the windows 10 enterprise iso file and click next
2.  select windows 10 enterprise for the version of windows to install and click next, click yes for the prompt
3.  choose the location of the VM and click next
4.  select maximum disk size to 60 GB and check split virtual disk into multiple files, then click next
5.  uncheck power on this machine and click finish
![windows10_specs](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/windows10_vm_specs%20.jpg)
6.  select edit virtual machine settings and remove the floppy drive
7.  select bridged for network connection under network adapter
8.  under memory select 4GB of ram just for the setup, after the setup is complete change it to 2GB
9.  click play virtual machine to start the VM up
10. quickly click the screen and press any key when prompted to do so
11. leave defaults and select next in the language section
12. click install now
13. click i accept the license terms and click next
14. check custom install for the type of installation and click next
15. we see a drive 0 unallocated space of 60 gb, click new, then click apply and click OK, click next
16. after the installation is complete, leave the default region as united states and click next
17. leave keyboard layout as the default value US and click next, skip second keyboard layout
18. after this setup is completed, we see a sign in with microsoft page, click on domain join instead option
19. under the whos going to be using this PC? section, enter a memorable username for this system for example “simlabuser1” 
![account1_setup](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/account1_setup.jpg)
20. under the create a memorable password section, enter a memorable password for this system for example “Password1”
![account1_password](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/account1_password.jpg)
21. choose the appropriate security questions and their answers and click next
22. click no for do more across devices with active history and decline help from digital assistant
23. turn off all the privacy settings for the device and click accept
24. from the VMWare taskbar select manage and click install vmware tools
25. click the DVD drive VMWare tools popup on the vm screen and click run setup64.exe and select yes
26. in vmware tools select complete as the setup type, click next and finally click install - click no in the restart prompt popup
27. search computer in the windows searchbar click view your pc name
28. click Rename this PC and give the system an appropriate name like “SIMLABPC1” and click restart now to reboot the system
![naming_pc](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/naming_pc.jpg)
29. follow the same steps and set up another windows 10 vm, this system can have the PC name as “SIMLABPC2” and have a user “simlabuser2” with the password “Password2”

PC names, and user account credentials so far are:

Domain name: SIMLAB.local

-   SIMLAB-DC Administrator:P@$$w0rd!
-   SIMLAB-PC1 simlabuser1:Password1
-   SIMLAB-PC2 simlabuser2:Password2

## setting up users, groups and policies in the domain

1.  login to the DC machine and enter the server manager dashboard
2.  click tools and select Active Directory Users and Computers(ADUC)
![aduc_interface](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/aduc_interface.jpg)
3.  on clicking SIMLAB.local, we can see the different organizational units like computers, users and managed service accounts
4.  right click SIMLAB.local and click New → organizational unit, name the OU as Groups and click OK
5.  go the users OU and copy and paste all the security groups to the Groups OU, this cleans out the Users OU to just have user accounts in the domain
![aduc_users](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/aduc_users.jpg)
![aduc_groups](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/aduc_groups%20.jpg)
7.  we can configure each user account by double clicking the account in the users OU
8.  in the users OU, right click anywhere and click New → User and give the appropriate details of the user in our first windows VM, that is
    -   First name: simlab
    -   Last name: user1
    -   User logon name: simlabuser1
    -   and click next
![domain_user1_creation](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/domain_user1_creation.jpg)
9.  next, enter the appropriate password for this user account which is “Password1” and uncheck user must change password at next logon and check password never expires and click finish
![domainuser1_password](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/domain_user1_passwordsetting.jpg)
10.  right click the simlabuser1 user and select copy to repeat the steps to create another user for SIMLABPC2
11. right click on the administrator account and click copy then enter the details
    -   first name: domain
    -   last name: admin
    -   User logon name: dadmin
12. give this account an appropriate password like “Password2025!@#” then check password never expires and click finish
13. copy the domain admin account we just created to create a service account that is a domain admin
    -   First name: SQL
    -   Last name: Service
    -   User logon name: SQLService
14. give this account an appropriate password like “MYpassword123#”, click next and click finish
15. double click the SQLService user and in Description enter password is “MYpassword123#” and click apply - network administrators usually do this to increase ease of access
now we have set up all the required users in the network, the user accounts are
![all_users_setup](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/all_users_setup.jpg)
16. close the ADUC menu
17. open the file and storage services menu under server manager
18. click Shares, then click the tasks dropdown and click the new share option
19. use all default settings to create the share except for share name, where we can set an appropriate name like “hackme”, under confirmation click create and click close
![hackme_share](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/hackme_share.jpg)
20. close the server manager
21. open a command prompt terminal - to create an SPN type the following command
    ```
    setspn -a SIMLAB-DC/SQLService.SIMLAB.local:60111 SIMLAB\\SQLService
    ```
22. verify that the SPN has been set for the account with this command
    ```
    setspn -T SIMLAB.local -Q */*
    ```
    the SPN we created for the account should show up in the end of the command output
![spn_setup](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/spn_setup.jpg)
23. close the command prompt terminal and search for group policy in the windows searchbar, open group policy management as administrator
24. click forest SIMLAB.local and go to SIMLAB.local under domains, right click SIMLAB.local and select create a GPO in this domain and link it here
25. set a name of Disable Windows Defender for this GPO and click OK
![create_GPO](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/create_GPO.jpg)
26. right click the Disable Windows Defender GPO and select Edit
27. move to Policies → Administrative Templates → Windows Components → Windows Defender Antivirus and click Turn off Windows Defender Antivirus by double clicking it and selecting Enabled, then click Apply and select OK
![setting_GPO](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/setting_GPO%20.jpg)
28. right click the GPO again and make sure that the enforced option is set to Yes for the GPO

## Adding to the two windows enterprise systems to the domain

1.  login to the SIMLABPC1 machine as simlabuser1
2.  go to This PC → C: drive and create a new folder named Share
3.  right click the Share folder and select properties, go to Sharing and click Share and click the share button, if prompted click on Yes, turn on network discovery and file sharing for all public networks, then click done
![PC1_share_setup](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/PC1_share_setup%20.jpg)
4.  get the IP address of the Domain controller by going to the command prompt in the windows server terminal and using the ipconfig command
5.  in the simlabpc1 system, right click on the internet access icon in the windows taskbar and select open network and internet settings
6.  click change adapter options and right click Ethernet0 and select properties
7.  double click on the IPv4 section and check the Use the following DNS server addresses, then type in the IP address of the domain controller and click OK and close the window
![dns_server_config](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/DNS_server_config.jpg)
8.  in the windows searchbar search for domain, click the Access work or school option
9.  click the + icon connect button
10. select join this device to a local Active directory domain in the under Alternate actions section
11. enter the name of the domain which is SIMLAB.local and click next
![joining_to_domain](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/joining_to_domain.jpg)
12. in the Join a domain prompt that opens up, enter the credentials of the Administrator account on the Domain controller and click OK, click skip and then click Restart Now
13. type the user logon name for simlabuser1 and login to the system - the system has been joined to the domain
14. sign out of the simlabuser1 account and sign in as simlab\administrator:P@$$w0rd!
15. go to computer management → Local Users and Groups → Groups → Administrators
16. add the user simlabuser1 which is the account on the domain, click Apply and then click OK
![simlab_user1_domain_admin](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/simlab_user1_domainadmin_on_SIMLAB-PC1.jpg)
17. follow the steps for the simlabuser2 system - join the system, to the domain
18. in Groups → Administrators this time, add both simlabuser1 and simlabuser2 as local admins on the system on SIMLABPC2 system
![simlab-pc2_domain_admins](https://github.com/whoismithun/Active-Directory-Network-Emulation/blob/e66dd6517235e87a5d146e7f6be22849079500f7/setup_images/simlab-pc2_user1anduser2_localadmin_on_SIMLAB-PC2.jpg)
19. if we now go to the domain controller system’s ADUC and refresh we will see the updated information of the 2 computers being added to the domain
