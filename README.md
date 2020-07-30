# My Machine, My JTAG

MMMJTAG is an asbtraction library meant to make debugging windows apps/drivers using Intel DCI through OpenIPC easier.

It also aims to evade anti-debugging. Some potential uses off of the top of my head are:

* Vulnerability research in software that doesn't like to be debugged
	* Antimalware
	* Actual malware that involves kernel components
	* Anticheat
	* DRM
	* etcetc...
* Bypassing bitlocker in cases where a PIN isn't in use, only a TPM
	* On most mobos, JTAG can be enabled without disturbing the TPM state. The PCRs will still match their expected values
* Exploration of VTL1
