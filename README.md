# Windows Kernel Exploitation.
Static & dynamic analysis, exploits & vuln reasearch. <br>
Mitigations bypass's <br>

# Contents:
HEVD-Vanilla-Bug-Class's:<br>
Exploits & Vuln Note's in order to reproduce & reuse.<br>
* <html><a href="https://github.com/akayn/demos/tree/master/HEVD-Vanilla-Bug-Class's">HEVD-Vanilla-Bug-Class's</a></html><br>
	[+] <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/Compiled.zip?raw=true">Compiled-win7x86</a></html><br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-TypeConfX86Win7.c">Type Confusion</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-ArbitraryOverwritex86win7.c">Arbitrary Overwrite</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-NullPointerDereference.c">Null Pointer Dereference</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-PoolOverFlow-Win7-x86.c">Pool OverFlow</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-StackOverFlowx86Win7.c">Stack OverFlow</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-Uaf-Win7x86.c">Use After Free</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-UninitializedStackVariableWin7x86.c">Uninitialized Stack Variable</a></html>.<br>

kd & dev:<br>
* ShellCode: <html><a href="https://github.com/akayn/demos/blob/master/Win10/PayLoads/TokenStealingShellCode.asm">pl.asm</a></html><br>
* kernelLeaks: <html><a href="https://github.com/akayn/demos/blob/master/Primitives/HMValidateBitmap.cc">leak bitmap bAddr with HMValidateHandle</a></html><br>

Mitigations Bypass:<br>
* [RS3-Compatible] ROP Based SMEP Bypass including Gadgets & full debugging info: <html><a href="https://github.com/akayn/demos/blob/master/Win10/SmepByPassWin10x64build.16281Rs3/SmepBypassX64Win10RS3.c">SmepBypassX64Win10RS3.c</a></html><br>
* [<= RS2-Compatible] BitMap Arbitrary OverWrite: <html><a href="https://github.com/akayn/demos/blob/master/Win10/BitMap_Win_10_15063.0.amd64fre.rs2_release.170317-1834/GdiExp.cc">GdiExp.cc</a></html><br>
* [!] NOTE: the above is not stable & will work 1/10 in the good case...
	i will fix in the future.

Re & exploits:<br>
* Study Case's:<br>
	[+] TODO<br>...<br>
	...<br><br>

# External Resources:
* Memory-Management:<br>
	[+] <html><a href="https://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-088-introduction-to-c-memory-management-and-c-object-oriented-programming-january-iap-2010/lecture-notes/">MIT</a></html>.<br>
* C programming:<br>
	[+] <html><a href="https://github.com/jamesroutley/write-a-hash-table">HASH TABLE</a></html>.<br>
* asseambly:<br>
	[+] <html><a href="https://www-s.acm.illinois.edu/sigwin/old/workshops/winasmtut.pdf">TUT</a></html>.<br>

* HEVD & Basics:<br>
	[+] <html><a href="https://github.com/hacksysteam/HackSysExtremeVulnerableDriver">HackSysExtremeVulnerableDriver</a></html>.<br>
	[+] <html><a href="http://www.fuzzysecurity.com/tutorials.html">B33F tuto</a></html>.<br>
			[^]            Some of the Vuln Note's in the code were taken from there. <br>
	[+] <html><a href="https://blahcat.github.io/2017/08/14/a-primer-to-windows-x64-shellcoding/">ShellCoding & kd</a></html>.<br>
* Mitigations:<br>
	[+] SMEP:<br>
		* <html><a href="https://en.wikipedia.org/wiki/Control_register#CR4">wiki</a></html>.<br>
		* <html><a href="http://j00ru.vexillium.org/?p=783">j00ru</a></html>.<br>
		* <html><a href="https://github.com/n3k/EKOParty2015_Windows_SMEP_Bypass">Enrique Nissim & Nicolas Economou</a></html>.<br>
		* <html><a href="https://www.coresecurity.com/blog/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-3-windows-hals-heap">PTE-OverWrite</a></html>.<br>
		* <html><a href="https://www.blackhat.com/presentations/bh-usa-08/Shacham/BH_US_08_Shacham_Return_Oriented_Programming.pdf">return oriented Programming</a></html>.<br>
	[+] k-ASLR:<br>
		* <html><a href="https://github.com/MortenSchenk/BHUSA2017">Morten Schenk</a></html>.<br>
	[+] ReadWrite Primitives: <br>
		* <html><a href="https://sensepost.com/blog/2017/abusing-gdi-objects-for-ring0-primitives-revolution/">abusing gdi objects</a></html>.<br>

Tools:<br>
* <html><a href="https://github.com/CoreSecurity/Agafi">gadget finder</a></html>.<br>
* <html><a href="https://github.com/akayn/GDIObjDump">gdi-dump windbg extension</a></html>.<br>
* <html><a href="http://www.iceswordlab.com/2017/06/14/Automatically-Discovering-Windows-Kernel-Information-Leak-Vulnerabilities_en/">digtool fuzzer</a></html>.<br>
* <html><a href="https://github.com/akayn/winafl">winafl</a></html>.<br>


Software:<br>
* <html><a href="https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit">kd</a></html>.<br>
* <html><a href="https://developer.microsoft.com/en-us/windows/hardware/download-symbols">Symbols</a></html>.<br>
* <html><a href="https://www.hex-rays.com/products/ida/">Ida</a></html>.<br>
* <html><a href="http://www.nasm.us/">NASM</a></html>.<br>
* <html><a href="https://mh-nexus.de/en/hxd/">Hxd</a></html>.<br>

# See Also:
* <html><a href="https://github.com/akayn/demos/tree/master/Win10/SmepByPassWin10x64build.16281Rs3">Smep PoC</a></html>.<br>
* <html><a href="https://github.com/akayn/demos/tree/master/Win10/BitMap_Win_10_15063.0.amd64fre.rs2_release.170317-1834">GdiExp</a></html>.<br>

# Credits
many tnx to all the great ppl b4 me that did much work already!<br>

* <html><a href="https://github.com/FuzzySecurity">b33f</a></html>.<br>
* <html><a href="https://github.com/cn33liz">cn33liz</a></html>.<br>
* <html><a href="https://github.com/tekwizz123">b33f</a></html>.<br>
* <html><a href="https://github.com/GradiusX">GradiusX</a></html>.<br>
* <html><a href="https://github.com/sam-b">sam-b</a></html>.<br>
& all others...

