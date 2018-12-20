# Thycotic Secret Server integration with Splunk Web Management credentials

## Prerequisites

* Account with PowerShell access on the nodes. (***BUILTIN\Administrators*** or ***BUILTIN\Remote Management Users***)
* Thycotic Secret Server version 10.5.00000 or higher. (May work on any 10.x version, but tested only on 10.5 and up.)

## Installation

## Scripts

* **Splunk-Heartbeat.ps1** - To test the validity of a credential on the Splunk instance.
	1. `$MACHINE` - The machine of the local Splunk Web account.
	2. `$USERNAME` - The login of the user to which the password heartbeat is checked against.
	3. `$PASSWORD` - The password to be checked.
* **Splunk-PassChange.ps1** - To change the password of a local Splunk web account.
	1. `$MACHINE` - The machine of the local Splunk Web account.
	2. `$USERNAME` - The login of the user to which the password heartbeat is checked against.
	3. `$PASSWORD` - The OLD password.
	4. `$NEWPASSWORD` - The NEW password.


## Templates