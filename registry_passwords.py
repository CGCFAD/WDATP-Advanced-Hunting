// Source: WDATP Shared Query
// Finds machines that store the Windows password as clear text in the registry. 
// Passwords stored as clear text, used by earlier versions of Windows during automatic logons, are a significant security risk.  
RegistryEvents 
| where EventTime > ago(7d) 
| where ActionType == "SetValue"
| where RegistryKeyValueName == "DefaultPassword"
| where RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 
| project EventTime, ComputerName, RegistryKey
| top 100 by EventTime
