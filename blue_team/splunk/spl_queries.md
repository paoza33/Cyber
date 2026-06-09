# Bibliothèque de requêtes SPL pour la détection et le threat hunting

> Bibliothèque personnelle de requêtes SPL pour la détection et le threat hunting, organisée par technique d'attaque et alignée sur MITRE ATT&CK. Les index, sourcetypes et seuils sont à adapter au contexte de chaque environnement.
> **Conventions de cette bibliothèque**
> - Index : `main` est utilisé par défaut dans les exemples. À adapter au contexte réel.
> - Sourcetypes : `WinEventLog:Security` (live UF) ou `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (Sysmon Olaf Hartong / TA-microsoft-sysmon).
> - Comptes machine : toujours filtrer `user!=*$` ou `Account_Name!=*$`.
> - IPv6-mappées IPv4 : nettoyer avec `rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"`.

---

## Sommaire

| # | Section |
|---|---|
| 1 | Authentication & Logon |
| 2 | Active Directory Attacks |
| 3 | Process Creation & Execution |
| 4 | Persistence |
| 5 | Network Activity |
| 6 | Lateral Movement |
| 7 | Defense Evasion |
| 8 | Credential Access |
| 9 | Data Exfiltration |
| 10 | Threat Hunting Exploratoires |
| 11 | Templates & patterns réutilisables |

---

# 1. Authentication & Logon

## 1.1 Failed logons - brute force / password spraying (par IP source)

**MITRE ATT&CK** : T1110.003, T1110.001

**Contexte** : détecter une IP source qui tente beaucoup de comptes différents (signe spraying) ou un compte qui voit beaucoup d'échecs (brute force).
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

**Champs clés à analyser** : `dc_user` (élevé = spraying), `Users`, `Source_Network_Address`, `Failure_Reason`.
**Variations utiles** :
- Filtrer spraying confirmé : `... | where dc_user > 5`
- Pivot par IP : `... | sort - dc_user`
- Cibler une fenêtre plus courte : `bin span=5m _time`

---

## 1.2 Brute force - connexions rapprochées sur un même compte

**MITRE ATT&CK** : T1110.001

**Contexte** : détecter beaucoup d'échecs sur le même compte sur une fenêtre courte.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
EventCode=4625
| stats count as login_attempts, range(_time) as period by Account_Name
| where period < 600
```

**Champs clés à analyser** : `login_attempts`, `period` (en secondes), `Account_Name`.
**Variations utiles** :
- Ajouter src IP : `... by Account_Name, src`
- Seuil minimum d'attempts : `| where period < 600 AND login_attempts > 10`

---

## 1.3 Brute force RDP via Zeek

**MITRE ATT&CK** : T1110.001

**Contexte** : RDP brute force détecté côté NSM (Zeek) - utile quand pas de visibilité 4625 sur les cibles.
**Source de logs requise** : Zeek RDP log
**Index typique** : `rdp_bruteforce`

```spl
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
```

**Champs clés à analyser** : `count`, `cookie` (variations = nombreux users tentés), `id.orig_h`, `id.resp_h`.

---

## 1.4 Brute force SSH via Zeek

**MITRE ATT&CK** : T1110.001

**Contexte** : SSH brute force détecté côté Zeek.
**Source de logs requise** : Zeek SSH log
**Index typique** : `ssh_bruteforce`

```spl
index="ssh_bruteforce" sourcetype="bro:ssh:json" auth_success="false"
| bin _time span=5m
| stats sum(auth_attempts) as attempts by _time, id.orig_h, id.resp_h, client, server
| where attempts>30
```

**Champs clés à analyser** : `attempts`, `client` (version SSH), `server`.

---

## 1.5 Brute force / user enum Kerberos via Zeek

**MITRE ATT&CK** : T1110.003, T1087

**Contexte** : énumération de comptes via AS-REQ vers DC. `KDC_ERR_PREAUTH_REQUIRED` est exclu (= comportement normal d'un client cherchant un user valide).
**Source de logs requise** : Zeek Kerberos log
**Index typique** : `kerberos_bruteforce`

```spl
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
```

**Champs clés à analyser** : `count`, `Unique users`, `Error messages` (`KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` = user invalide).

---

## 1.6 Pre-auth failures Kerberos (4771) - équivalent côté DC

**MITRE ATT&CK** : T1110.001

**Contexte** : détecter brute force Kerberos via le log natif Windows du DC (alternative à Zeek).
**Source de logs requise** : Windows Security log (DC)
**Index typique** : `main`

```spl
index=main source="WinEventLog:Security" EventCode=4771
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| bin _time span=15m
| stats count, dc(TargetUserName) as dc_user, values(Status) as Status by _time, src_ip
| where count > 30 OR dc_user > 5
```

**Champs clés à analyser** : `Status` (`0x18` = bad password, `0x6` = user inconnu), `dc_user`.

---

## 1.7 Account lockouts (4740)

**MITRE ATT&CK** : T1110

Pattern type :

```spl
index=main source="WinEventLog:Security" EventCode=4740
| stats count by TargetUserName, TargetDomainName, host
| sort - count
```

---

## 1.8 Logons hors heures ouvrées

**MITRE ATT&CK** : T1078

Pattern type :

```spl
index=main source="WinEventLog:Security" EventCode=4624 user!=*$
| eval hour = strftime(_time, "%H")
| eval dow  = strftime(_time, "%A")
| where (hour < 7 OR hour > 19) OR dow IN ("Saturday","Sunday")
| stats count by user, dest, hour, dow
| sort - count
```

---

## 1.9 Privilèges spéciaux assignés à une nouvelle session (4672)

**MITRE ATT&CK** : T1078

**Contexte** : apparition récente de droits admin sur un compte (signal Silver Ticket / nouvel admin).
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| where firstTime > relative_time(now(),"-24h")
| convert ctime(firstTime)
| table firstTime, ComputerName, Account_Name
```

**Champs clés à analyser** : `firstTime`, `Account_Name`, `ComputerName`.

---

## 1.10 Logon explicite (4648) - runas / mouvement latéral

**MITRE ATT&CK** : T1078, T1021

**Contexte** : événement émis pour `runas` ou connexion explicite avec credentials différents (signal Responder, mouvement latéral, pivot Kerberoasting).
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main EventCode=4648
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

**Champs clés à analyser** : `Target_Server_Name`, `Subject_User_Name`, `Target_User_Name`.

---

# 2. Active Directory Attacks

## 2.1 Kerberoasting - recon LDAP via SilkService

**MITRE ATT&CK** : T1558.003

**Contexte** : détecter la phase de recon (recherche LDAP de comptes avec SPN) - antérieure aux 4769 RC4.
**Source de logs requise** : SilkService log custom (ETW LDAP-Client)
**Index typique** : `main`

```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

**Champs clés à analyser** : `SearchFilter`, `ProcessName`, `ComputerName`.

---

## 2.2 Kerberoasting - TGS sans logon explicite suivant (méthode `stats`)

**MITRE ATT&CK** : T1558.003

**Contexte** : un TGS pour un service sans 4648 dans la fenêtre suivante = pas d'accès légitime au service après le ticket → roasting probable.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time
| search username!=*$
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

**Champs clés à analyser** : `username`, `service_name`, `Target_Server_Name`.
**Variations utiles** : adapter `service_name=iis_svc` à un autre service / lookup multi-services.

---

## 2.3 Kerberoasting - variante `transaction`

**MITRE ATT&CK** : T1558.003

**Contexte** : version élégante mais coûteuse de la requête précédente. Préférer 2.2 en prod.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)
| where closed_txn=0 AND EventCode=4769
| table _time, EventCode, service_name, username
```

---

## 2.4 Kerberoasting - RC4 forcé (Zeek)

**MITRE ATT&CK** : T1558.003

**Contexte** : détection comportementale via `cipher=rc4-hmac` + `forwardable=true` + `renewable=true`.
**Source de logs requise** : Zeek Kerberos log
**Index typique** : `sharphound`

```spl
index="sharphound" sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac"
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```

**Champs clés à analyser** : `client`, `service`, `id.orig_h`.

---

## 2.5 AS-REPRoasting - recon LDAP via SilkService

**MITRE ATT&CK** : T1558.004

**Contexte** : recon LDAP des comptes avec `DONT_REQUIRE_PREAUTH` (bit `4194304`).
**Source de logs requise** : SilkService log
**Index typique** : `main`

```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

---

## 2.6 AS-REPRoasting - 4768 avec Pre_Authentication_Type=0

**MITRE ATT&CK** : T1558.004

**Contexte** : la signature serveur côté DC.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

**Champs clés à analyser** : `Pre_Authentication_Type=0`, `user`, `src_ip`.

---

## 2.7 Pass-the-Hash - détection simple (LogonType 9 + seclogo)

**MITRE ATT&CK** : T1550.002

**Contexte** : détection minimale, génère des faux positifs sur `runas /netonly` légitime → préférer 2.8.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

---

## 2.8 Pass-the-Hash - détection renforcée (LogonType 9 + accès LSASS)

**MITRE ATT&CK** : T1550.002, T1003.001

**Contexte** : élimine les `runas /netonly` légitimes en exigeant un accès LSASS (Sysmon EID 10) dans la même minute.
**Source de logs requise** : Windows Security log + Sysmon
**Index typique** : `main`

```spl
index=main (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

**Champs clés à analyser** : `SourceImage`, `Network_Account_Name`, `Computer`.

---

## 2.9 Pass-the-Ticket / Golden Ticket - TGS sans TGT préalable

**MITRE ATT&CK** : T1550.003, T1558.001

**Contexte** : un TGS (4769) sans 4768 préalable dans la fenêtre = ticket forgé/volé injecté.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

**Champs clés à analyser** : `username`, `src_ip_4`, `service_name`.

---

## 2.10 Golden Ticket - anomalie comportementale (Zeek)

**MITRE ATT&CK** : T1558.001

**Contexte** : source qui ne fait que TGS, jamais AS-REQ → anomalie absolue.
**Source de logs requise** : Zeek Kerberos log
**Index typique** : `golden_ticket_attack`

```spl
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
```

---

## 2.11 Silver Ticket - users inconnus connectés (corrélation users.csv)

**MITRE ATT&CK** : T1558.002

**Contexte** : workflow en 2 étapes - bâtir la liste de référence des users légitimes, puis chercher les logons hors liste.
**Source de logs requise** : Windows Security log
**Index typique** : `main`
**Étape 1 - bâtir la liste de référence** :

```spl
index=main EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

**Étape 2 - chercher les logons sans match** :

```spl
index=main EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| where firstTime > relative_time(now(),"-24h")
| convert ctime(firstTime)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```

**Champs clés à analyser** : `user` non présent dans `users.csv`, `ComputerName`.

---

## 2.12 Silver Ticket - pivot pour identifier le service compromis

**MITRE ATT&CK** : T1558.002

**Contexte** : une fois un user inconnu identifié sur un host, identifier quel compte de service a été compromis.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main "<username_inconnu>" "<HOSTNAME>"
| stats count by EventCode
```

> Lire ensuite les 4648 pour identifier `Additional Information: cifs/sqlserver` → service CIFS compromis.

---

## 2.13 DCSync - détection minimale (Access_Mask 0x100)

**MITRE ATT&CK** : T1003.006

**Contexte** : 4662 sur DS avec accès "Replicating Directory Changes" + non-compte machine.
**Source de logs requise** : Windows Security log (audit DS Access activé)
**Index typique** : `main`

```spl
index=main EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```

---

## 2.14 DCSync - détection détaillée (avec parsing du Message)

**MITRE ATT&CK** : T1003.006

**Contexte** : extraire le détail "Replicating Directory Changes" depuis le Message.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

**Champs clés à analyser** : `user` (doit ne pas être un DC légitime), `property`.

---

## 2.15 DCShadow - ajout de SPN Global Catalog (4742)

**MITRE ATT&CK** : T1207

**Contexte** : ajout d'un SPN `XX/MACHINE.corp.local` (global catalog) à un compte machine = enregistrement comme faux DC.
**Source de logs requise** : Windows Security log
**Index typique** : `main`

```spl
index=main EventCode=4742
| rex field=Message "(?P<gcspn>XX\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```

> Pour identifier le préfixe SPN à matcher : d'abord `index=main EventCode=4742 | table _time, ComputerName, Message` et lire `Service Principal Names: XX/MACHINE.corp.local`.

---

## 2.16 Constrained Delegation - recon PowerShell (4104)

**MITRE ATT&CK** : T1558

**Contexte** : EID 4104 PowerShell révèle les recherches sur attribut de délégation.
**Source de logs requise** : PowerShell Operational
**Index typique** : `main`

```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*"
| table _time, ComputerName, EventCode, Message
```

```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
```

---

## 2.17 Constrained Delegation - connexion Rubeus port 88 (Sysmon)

**MITRE ATT&CK** : T1558

**Contexte** : détection comportementale de Rubeus s4u via Sysmon EID 3 vers DC port 88 depuis process ≠ lsass.exe.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

---

## 2.18 Overpass-the-Hash - connexion Kerberos depuis process inhabituel

**MITRE ATT&CK** : T1550.002

**Contexte** : Mimikatz overpass se détecte comme PtH (cf. 2.8) ; Rubeus génère 4768 légitime → utiliser Sysmon EID 3 port 88 depuis process ≠ lsass.exe.
**Source de logs requise** : Sysmon (process create + network)
**Index typique** : `main`

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

**Pattern réutilisable** : `eventstats values(process) as process by process_id` enrichit les events réseau (EID 3) avec la commandline du process (EID 1).

---

## 2.20 Password spraying - Kerberos (codes erreurs 4768)

**MITRE ATT&CK** : T1110.003

```spl
index=main source="WinEventLog:Security" EventCode=4768 (Result_Code=0x6 OR Result_Code=0x12)
| bin span=15m _time
| stats dc(TargetUserName) as dc_user, count by _time, IpAddress, Result_Code
| where dc_user > 5
```

---

## 2.21 Password spraying - NTLM (4776)

**MITRE ATT&CK** : T1110.003

```spl
index=main source="WinEventLog:Security" EventCode=4776 Status="0xC0000064"
| bin span=15m _time
| stats dc(TargetUserName) as dc_user, count by _time, Workstation
| where dc_user > 5
```

> Codes `0xC0000064` = user inexistant, `0xC000006A` = mauvais MDP.

---

## 2.22 Recon AD natif - multi-commands depuis même parent (Sysmon EID 1)

**MITRE ATT&CK** : T1087.002, T1059

**Contexte** : un même parent qui lance plus de 3 commandes de recon (whoami/net/nltest/ipconfig...) = signal fort de recon manuelle / scripts d'attaquant.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

**Champs clés à analyser** : `parent_process`, nombre de `process` distincts.

---

## 2.23 BloodHound / SharpHound - LDAP via SilkService

**MITRE ATT&CK** : T1087.002

**Contexte** : SharpHound bombarde le DC de LDAP. Filtre `samAccountType=805306368` = listage users.
**Source de logs requise** : SilkService log custom
**Index typique** : `main`

```spl
index=main earliest=<ts> latest=<ts> source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

**Variation utile (pivot pour identifier le user)** :

```spl
index=main EventCode=1 ProcessId=<PID>
| table _time, Computer, User, Image, CommandLine
```

---

## 2.24 BloodHound via RPC (alternative LDAP)

**MITRE ATT&CK** : T1087.002

**Contexte** : BloodHound peut utiliser des appels DCE/RPC plutôt que LDAP - détection via Zeek `dce_rpc.log`.
**Source de logs requise** : Zeek DCE/RPC
**Index typique** : `bloodhound_all_no_kerberos_sign`

```spl
index="bloodhound_all_no_kerberos_sign" sourcetype="bro:dce_rpc:json"
operation IN ("NetrSessionEnum", "NetrWkstaUserEnum", "SamrGetMembersInAlias", "SamrOpenDomain", "SamrConnect5", "SamrCloseHandle")
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

---

## 2.25 Zerologon (CVE-2020-1472) - flood Netlogon RPC

**MITRE ATT&CK** : T1210

**Contexte** : >100 reqs/min sur endpoint `netlogon` avec ≥2 opérations distinctes.
**Source de logs requise** : Zeek DCE/RPC
**Index typique** : `zerologon`

```spl
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation=="NetrServerReqChallenge" OR operation=="NetrServerAuthenticate3" OR operation=="NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```

---

## 2.26 PrintNightmare - RpcAddPrinterDriverEx via spoolss

**MITRE ATT&CK** : T1068

**Source de logs requise** : Zeek DCE/RPC
**Index typique** : `printnightmare`

```spl
index="printnightmare" sourcetype="bro:dce_rpc:json"
endpoint=spoolss operation=RpcAddPrinterDriverEx
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

---

# 3. Process Creation & Execution

## 3.1 Process create - vue parent → enfant (Sysmon EID 1)

**MITRE ATT&CK** : T1059

**Contexte** : top des relations parent-enfant pour identifier les chaînes anormales.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
| stats count by ParentImage, Image
```

**Variation - cibler shells suspects** :

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
(Image="*cmd.exe" OR Image="*powershell.exe")
| stats count by ParentImage, Image
```

---

## 3.3 Process creation 4688

**MITRE ATT&CK** : T1059

```spl
index=main source="WinEventLog:Security" EventCode=4688
| stats count by NewProcessName, ParentProcessName, host
| sort - count
```

---

## 3.4 Suspicious parent-child relationships

**MITRE ATT&CK** : T1059

Pattern type :

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\powerpnt.exe","*\\outlook.exe")
Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe","*\\rundll32.exe","*\\regsvr32.exe")
| table _time, host, User, ParentImage, Image, CommandLine
```

---

## 3.5 LOLBins - exécution depuis un parent inhabituel

**MITRE ATT&CK** : T1218

Pattern type :

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image IN ("*\\msbuild.exe","*\\installutil.exe","*\\regsvr32.exe","*\\rundll32.exe","*\\mshta.exe","*\\certutil.exe","*\\bitsadmin.exe","*\\wmic.exe")
| stats count by Image, ParentImage, CommandLine
| sort - count
```

---

## 3.6 PowerShell - recherche dans le contenu des scripts (4104)

**MITRE ATT&CK** : T1059.001

**Contexte** : Script Block Logging logue le **contenu** des scripts PowerShell.
**Source de logs requise** : PowerShell Operational
**Index typique** : `main`

```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*<motif>*"
| table _time, ComputerName, EventCode, Message
```

**Patterns clés** : `TrustedForDelegation`, `userAccountControl:=524288`, `msDS-AllowedToDelegateTo`.

---

## 3.7 PowerShell encodé (CommandLine > 1000 chars)

**MITRE ATT&CK** : T1059.001, T1027

**Contexte** : heuristique simple = CommandLine PowerShell anormalement longue → Base64/obfuscation.
**Source de logs requise** : Sysmon EID 1 ou 4688
**Index typique** : `main`

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe"
| eval cmd_len = len(CommandLine)
| where cmd_len > 1000
| table _time, host, User, ParentImage, Image, CommandLine, cmd_len
| sort - cmd_len
```

**Champs clés** : `cmd_len`, `CommandLine` (chercher `-enc`, `-encodedcommand`, Base64).

---

## 3.8 WMI execution (Sysmon 19/20/21)

**MITRE ATT&CK** : T1047

Pattern type :

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
| table _time, host, User, EventCode, Operation, Consumer, Filter, EventNamespace
```

---

## 3.9 Scheduled task creation

**MITRE ATT&CK** : T1053.005

Pattern type :

```spl
index=main source="WinEventLog:Security" EventCode IN (4698,4700,4701,4702)
| table _time, host, SubjectUserName, TaskName, TaskContent
| sort - _time
```

---

# 4. Persistence

## 4.1 Service installation (7045)

**MITRE ATT&CK** : T1543.003

Pattern type :

```spl
index=main source="WinEventLog:System" EventCode=7045
| table _time, host, ServiceName, ImagePath, ServiceType, StartType
| sort - _time
```

---

## 4.2 Création/modification de service distant (DCE/RPC svcctl)

**MITRE ATT&CK** : T1543.003

**Contexte** : SharpNoPSExec / Cobalt Strike créent ou modifient des services distants via RPC svcctl.
**Source de logs requise** : Zeek DCE/RPC
**Index typique** : `change_service_config`

```spl
index="change_service_config" endpoint=svcctl sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "ChangeServiceConfigW")
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

---

## 4.3 Registry Run keys (Sysmon EID 13)

**MITRE ATT&CK** : T1547.001

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
TargetObject IN ("*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                 "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                 "*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\*")
| table _time, host, User, Image, TargetObject, Details
```

---

# 5. Network Activity

## 5.1 Connexions Sysmon EID 3 - vue globale

**MITRE ATT&CK** : T1071

Pattern type :

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
NOT (DestinationIp="10.0.0.0/8" OR DestinationIp="172.16.0.0/12" OR DestinationIp="192.168.0.0/16")
| stats count, dc(DestinationIp) as dc_dest by Image, User
| sort - count
```

---

## 5.2 Beaconing C2 - détection par régularité des intervalles (Zeek HTTP)

**MITRE ATT&CK** : T1071.001

**Contexte** : pour chaque triplet src/dest/dest_port, calculer l'intervalle entre paquets, comparer à la moyenne, garder les flux dont >90% des intervalles sont dans ±10% de la moyenne.
**Source de logs requise** : Zeek HTTP
**Index typique** : `cobaltstrike_beacon`

```spl
index="cobaltstrike_beacon" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
```

**Champs clés à analyser** : `prcnt`, `TimeInterval`, `total`.
**Variations utiles** : assouplir si rien ne sort → `prcnt > 85`, `total > 5`.

---

## 5.3 Beaconing - quick check visuel

**MITRE ATT&CK** : T1071.001

**Contexte** : pour valider rapidement un pattern de beaconing identifié.
**Source de logs requise** : Zeek HTTP
**Index typique** : `cobaltstrike_beacon`

```spl
index="cobaltstrike_beacon" sourcetype="bro:http:json" id.orig_h="<src>" id.resp_h="<dst>"
| timechart span=10s count
```

---

## 5.4 Nmap port scanning (Zeek conn)

**MITRE ATT&CK** : T1046

**Contexte** : `orig_bytes=0` + plusieurs ports différents vers même cible interne.
**Source de logs requise** : Zeek conn
**Index typique** : `cobaltstrike_beacon`

```spl
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
| bin span=5m _time
| stats dc(dest_port) as num_dest_port, values(dest_port) as dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 3
```

---

## 5.5 DNS queries (Sysmon EID 22) - Responder / LLMNR poisoning

**MITRE ATT&CK** : T1557.001

**Contexte** : un nom DNS inexistant qui résout = Responder actif sur le LAN.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
index=main EventCode=22
| table _time, Computer, user, Image, QueryName, QueryResults
```

**Variation utile (LLMNR Detection custom)** :

```spl
index=main SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

> Setup côté endpoint : `New-EventLog -LogName Application -Source LLMNRDetection` + `Write-EventLog ... EventId 19001`.

---

## 5.6 Long-lived connections

**MITRE ATT&CK** : T1071

Pattern type :

```spl
index=main sourcetype="bro:conn:json"
| where duration > 3600
| stats count, sum(orig_bytes) as bytes_out, sum(resp_bytes) as bytes_in by src_ip, dest_ip, dest_port, duration
| sort - duration
```

---

## 5.7 Enrichissement Sysmon - relier connexion (EID 3) à process (EID 1)

**MITRE ATT&CK** : T1071

**Contexte** : pattern réutilisable pour enrichir n'importe quelle requête réseau Sysmon avec la commandline du process via `process_id`.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=<PORT>) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
```

> Pattern réutilisable : remplacer `dest_port=<PORT>` par n'importe quel port suspect.

---

# 6. Lateral Movement

## 6.1 PSExec / Cobalt Strike - push binaire via SMB ADMIN$

**MITRE ATT&CK** : T1021.002, T1570

**Contexte** : SharpHound, PSExec, Cobalt Strike déposent un binaire sur `\\C$` ou `\\ADMIN$`.
**Source de logs requise** : Zeek SMB Files
**Index typique** : `cobalt_strike_psexec`

```spl
index="cobalt_strike_psexec" sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```

---

## 6.3 RDP - détection (LogonType 10)

**MITRE ATT&CK** : T1021.001

Pattern SPL équivalent :

```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=10
| table _time, ComputerName, user, Source_Network_Address, Logon_Type
| sort - _time
```

**Variation suspecte (compte de service en RDP)** :

```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=10 user=svc-*
| table _time, ComputerName, user, Source_Network_Address
```

---

## 6.4 SMB - accès partages (4624 LogonType 3)

**MITRE ATT&CK** : T1021.002

```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=3
user!=*$ NOT (Source_Network_Address="-" OR Source_Network_Address="::1")
| stats dc(ComputerName) as dc_dest, count by user, Source_Network_Address
| sort - dc_dest
```

---

# 7. Defense Evasion

## 7.1 Event log clearing (1102)

**MITRE ATT&CK** : T1070.001

```spl
index=main source="WinEventLog:Security" EventCode=1102
| table _time, host, SubjectUserName, SubjectLogonId
```

---

## 7.3 Process injection - détection avancée (CallTrace UNKNOWN)

**MITRE ATT&CK** : T1055

**Contexte** : CallTrace contenant `UNKNOWN` = appel depuis mémoire allouée (shellcode/reflective DLL). Filtrer les faux positifs .NET.
**Source de logs requise** : Sysmon EID 10
**Index typique** : `main`

```spl
index="main" CallTrace="*UNKNOWN*"
  SourceImage!="*Microsoft.NET*"
  CallTrace!=*ni.dll*
  CallTrace!=*clr.dll*
  CallTrace!=*wow64*
  SourceImage!="C:\\Windows\\Explorer.EXE"
| where SourceImage!=TargetImage
| stats count by SourceImage, TargetImage, CallTrace
```

---

## 7.4 LSASS access (Sysmon EID 10) - credential dumping

**MITRE ATT&CK** : T1003.001

**Contexte** : tout process accédant à `lsass.exe` est suspect. Filtrer Defender.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
index=main EventCode=10 lsass
| stats count by SourceImage
```

**Variation renforcée - GrantedAccess Mimikatz** :

```spl
index=main EventCode=10 TargetImage="*lsass.exe"
GrantedAccess IN ("0x1010","0x1410","0x1FFFFF")
SourceImage!="*\\MsMpEng.exe"
| stats count by _time, host, SourceImage, GrantedAccess, CallTrace
```

---

## 7.5 Image Load anomalies (Sysmon EID 7)

**MITRE ATT&CK** : T1574

- DLL non signée (`Signed=false`) chargée depuis chemin atypique
- `clr.dll`/`clrjit.dll` chargé par `spoolsv.exe`/`lsass.exe` (BYOL .NET)
Pattern type :

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
ImageLoaded IN ("*\\clr.dll","*\\clrjit.dll","*\\mscoree.dll")
Image IN ("*\\spoolsv.exe","*\\lsass.exe","*\\winlogon.exe","*\\services.exe")
| stats count by host, Image, ImageLoaded, Signed
```

---

# 8. Credential Access

## 8.5 SAM hive access

**MITRE ATT&CK** : T1003.002

Pattern type (Sysmon EID 11 / 13 sur SAM) :

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(EventCode=11 TargetFilename="*\\Windows\\System32\\config\\SAM*") OR
(EventCode=13 TargetObject="*\\SAM\\SAM\\Domains*")
| table _time, host, User, Image, TargetFilename, TargetObject
```

---

# 9. Data Exfiltration

## 9.1 Exfiltration HTTP - volume POST sortant

**MITRE ATT&CK** : T1041

**Contexte** : agréger le volume POST par triplet src/dest/port - volume anormal = exfil.
**Source de logs requise** : Zeek HTTP
**Index typique** : `cobaltstrike_exfiltration_http`

```spl
index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
```

**Champs clés à analyser** : `TotalBytes` (en MB).

---

## 9.2 Exfiltration DNS - sous-domaines anormalement longs

**MITRE ATT&CK** : T1048.003

**Contexte** : DNS tunneling = champ TXT / sous-domaines très longs depuis un même hôte.
**Source de logs requise** : Zeek DNS
**Index typique** : `dns_exf`

```spl
index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day
```

**Champs clés à analyser** : `req_by_day`, `id.orig_h` (hôte interne suspect).
**Variations utiles** : assouplir `len_query>=40` → `>=30` ; ajuster les exclusions selon ton environnement (CDN, voice).

---

## 9.3 Ransomware (SMB) - Sodinokibi (overwrite : FILE_OPEN + FILE_RENAME en masse)

**MITRE ATT&CK** : T1486

**Contexte** : signature de chiffrement de masse - beaucoup d'opérations FILE_OPEN suivies de FILE_RENAME.
**Source de logs requise** : Zeek SMB Files
**Index typique** : `ransomware_open_rename_sodinokibi`

```spl
index="ransomware_open_rename_sodinokibi" sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```

---

## 9.4 Ransomware (SMB) - CTBLocker (renaming en masse vers une nouvelle extension)

**MITRE ATT&CK** : T1486

**Source de logs requise** : Zeek SMB Files
**Index typique** : `ransomware_new_file_extension_ctbl_ocker`

```spl
index="ransomware_new_file_extension_ctbl_ocker" sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME"
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort -count
```

**Champs clés à analyser** : `new_file_name_extension` (extension malveillante typique : `.locked`, `.encrypted`...), `count`.

---

# 10. Threat Hunting Exploratoires

## 10.1 Anomaly hunting - processus rares

**Contexte** : le processus le moins fréquent est souvent le plus intéressant.

```spl
| rare limit=10 Image
| rare limit=10 User
```

---

## 10.2 Subsearch d'exclusion - exclure les processus communs

**Contexte** : retirer les top processus pour faire émerger les rares.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
EventCode=1 NOT [search EventCode=1 | top Image | fields Image]
```

---

## 10.3 Cartographie initiale d'un environnement Splunk (exploration)

**Contexte** : utile en début de Sherlock - quels index/sourcetypes/sources existent ?

```spl
| eventcount summarize=false index=* | table index
| metadata type=sourcetypes | table sourcetype
| metadata type=sources | table source
| fieldsummary
```

---

## 10.5 Top N analysis

```spl
index=main <filtre>
| top limit=10 <field>
| sort - count
```

---

## 10.6 Transactions process create + connexion réseau rapides

**MITRE ATT&CK** : T1071

**Contexte** : signal C2 / loader - process créé → connexion sortante immédiate.
**Source de logs requise** : Sysmon
**Index typique** : `main`

```spl
EventCode=1 OR EventCode=3
| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m
```

---

# 11. Templates & patterns réutilisables

## 11.1 Nettoyage IPv6-mappées IPv4

```spl
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
```

## 11.2 Extraction username depuis UPN

```spl
| rex field=user "(?<username>[^@]+)"
```

## 11.3 Exclure les comptes machine

```spl
... user!=*$
... Account_Name!=*$
... NOT user="*$@*"
```

## 11.4 Bin / streamstats / eventstats - patterns

| Pattern | Usage |
|---|---|
| `bin _time span=15m` | Découper en fenêtres pour stats |
| `streamstats current=f last(_time) as prevtime by ...` | Calculer un delta entre paquets |
| `eventstats values(process) as process by process_id` | Enrichir sans réduire les events |
| `transaction X maxspan=10h startswith=(...) | where closed_txn=0` | Détecter une chaîne incomplète |
| `outputlookup users.csv` puis `lookup users.csv ... OUTPUT` | Bâtir + utiliser une référence |
| `convert ctime(field)` | Convertir epoch → lisible |
| `relative_time(now(),"-24h")` | Filtre temporel relatif |

## 11.5 Workflow universel (rappel)

```
1) index= + time
2) filtre EventCode
3) table / stats
4) enrichissement (eval / rex / lookup / spath)
```

## 11.8 Seuils de hunt typiques

| Métrique | Seuil hunt |
|---|---|
| Beaconing : `prcnt` connexions dans intervalle ±10% | `> 90%` AND `total > 10` |
| Nmap port scan : ports différents par 5 min | `dc(dest_port) >= 3` |
| Kerberos brute force : users distincts par 5 min | `count > 30` |
| RDP brute force : connexions par 5 min | `count > 30` |
| SSH brute force : auth_attempts par 5 min | `attempts > 30` |
| DNS exfil : longueur query | `len(query) >= 40` |
| DNS exfil : requêtes par jour | `> 60` |
| Ransomware Sodinokibi | `count > 100` AND `uniq_actions == 2` |
| Ransomware CTBLocker | `count > 20` (par extension) |
| Recon AD : commandes distinctes même parent | `mvcount(process) > 3` |
| BloodHound LDAP | `count > 10` requêtes par PID |
| 4672 récent | `firstTime > relative_time(now(),"-24h")` |
| Brute force compte | `period < 600` (10 min) |

---