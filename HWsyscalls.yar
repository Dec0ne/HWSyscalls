/*
   YARA Rule Set
   Author: Ido Veltzman, Mor Davidovich
   Date: 2023-02-11
   Identifier: Release
   Reference: https://github.com/Dec0ne/HWSyscalls
*/

rule HWSyscalls {
   meta:
      description = "HWSyscalls yara rule"
      author = "Ido Veltzman, Mor Davidovich"
      reference = "https://github.com/Dec0ne/HWSyscalls"
      date = "2023-02-11"
   strings:
      $s2 = "VCRUNTIME140_1.dll" fullword ascii
      $s4 = "[+] Jumping to \"ret;\" gadget address: 0x%I64X" fullword ascii
      $s5 = "[+] Continuing with normal execution" fullword ascii
      $s6 = "2b607363353b" ascii /* hex encoded string '+`sc5;' */
      $s7 = "32706a6d3e30" ascii /* hex encoded string '2pjm>0' */
      $s8 = "[+] Kernel32 Proxy Function Breakpoint Hit (%#llx)!" fullword ascii
      $s9 = "[+] Moving breakpoint to Kernel32 proxy function: 0x%I64X" fullword ascii
      $s10 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s11 = "[+] Jumping to \"call REGISTER;\" gadget address: 0x%I64x" fullword ascii
      $s12 = "[!] Could not find a suitable \"CALL REGISTER\" gadget in kernel32 or kernelbase. InitHWSyscalls failed." fullword ascii
      $s13 = "[+] Found %s address: 0x%I64X" fullword ascii
      $s14 = "[-] Could not set new thread context: 0x%X" fullword ascii
      $s15 = "invalid vector subscript" fullword ascii
      $s16 = "[+] callRegGadgetAddressRet Breakpoint Hit (%#llx)!" fullword ascii
      $s17 = "[+] Moving breakpoint to callRaxGadgetAddressRet to catch the return from NTAPI function: 0x%I64X" fullword ascii
      $s18 = "[+] Setting REGISTER value to NTAPI function address: 0x%I64X" fullword ascii
      $s19 = "[-] Could not find SSN" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}
