```
@author:	Michael Denzel
@license:	GNU General Public License 2.0 or later
```

------------------------------------------------

```
1. Installation
2. Quickstart
3. Usage
 3.1 dumpACPITables.py
 3.2 scanACPITables.py
4. Remarks
 4.1 iasl
 4.2 ACPIstructs.py
```

------------------------------------------------

# 1. Installation

Just copy the three files

- ACPIstructs.py ("header" file)
- dumpACPITables.py
- scanACPITables.py

to the plugin-folder of volatility (.../volatility/plugins).

Both plugins (dumpACPITables.py and scanACPITables.py) can be installed and run
individually and just require the header-file ACPIstructs.py

Alternatively, one can include `--plugins=.../ACPI-rootkit-scan` in the volatility command.

------------------------------------------------

# 2. Quickstart

Simply execute:

```volatility --plugins=/path/to/ACPI-rootkit-scan --profile=xxx -f /path/to/dump.dd scanacpitables --dump```

The option 'dump' calls both modules with default option, i.e. it dumps the ACPI tables into the default
folder, decompiles them with iasl, and scans the result for ACPI rootkits.

If you only want to see certain detections, run:

```volatility --plugins=/path/to/ACPI-rootkit-scan --profile=xxx -f /path/to/dump.dd scanacpitables --dump --only_crit```

------------------------------------------------

# 3. Usage
## 3.1 dumpACPITables.py

The plugin is able to extract the ACPI tables from a memory dump in raw and
aml format (for description of the parameters see "-h" option in volatility).
The files are extracted to a special folder e.g. ./dumpedTables/ and sub-folders
are created for every base pointer (RSDP) found in the specified memory region.

For example: ./dumpedTables/0x0009d510/ for an RSDP at 0x0009d510

A dump could look like the following:
```
$ tree ./dumpedTables
  0x0009d510
  |-- APIC.raw
  |-- BOOT.raw
  |-- DSDT.aml
  |-- FACP.raw
  |-- FACS.raw
  |-- HPET.raw
  |-- MCFG.raw
  |-- SRAT.raw
  `-- WAET.raw
  0x000f6b80
  |-- APIC.raw
  |-- BOOT.raw
  |-- DSDT.aml
  |-- FACP.raw
  |-- FACS.raw
  |-- HPET.raw
  |-- MCFG.raw
  |-- SRAT.raw
  `-- WAET.raw
```

## 3.2 scanACPITables.py

This plugin scans all .dsl (ACPI Source Language, ASL) files in a given path
for possible malicious function calls. To alter the path to search for
files see the "-p" option. Default is "./dumpedTables" and a folder named
after the RSDP pointer like in the dumpACPITables.py plugin.

If you wish to review the files by yourself, you could use the dumpACPITables.py plugin
in combination with iasl and a text-editor.

The dumped .aml (ACPI Machine Language, AML) files have to be decompiled first.
This can be done with the official tool iasl. (see also 3.1)


scanACPITables.py scans for a few functions that could be critical:

- Load/LoadTable/Unload => can be used to load further malicious code from a memory location
  it could be useful to further investigate this memory location
- IRQ1 => this is the keyboard interrupt. ACPI should not listen to this interrupt, if so
  there could be a keylogger installed.
- two PNP03* devices => that means two keyboard drivers exist in ACPI. This could also be
  a hint to manipulation and a possible keylogger.
- OperationRegion => any access to memory or devices has to be declared in an OperationRegion-Call.
  So every rootkit or malware has to use this function to access memory and change the system.
  The main idea of this plugin is to scan for these calls and compare the included address
  to kernel space (which includes the Interrupt Descriptor Table IDT and the System Service Dispatch Table
  in Windows for example - Tables that are often hooked by rootkits).

The result of a scan is evaluated in 4 Levels:

- "seems ok"	= the plugin could not find any hint to critical behaviour (this does not mean that there is none!)
- "unknown"	= a special function call could not be evaluated. This could be due to arguments and parameters passed
		  to the call. Since we are evaluating a memory image, these information are not available.
- "suspicious"	= something seems strange with this issue. Further investigations would be good.
- "CRITICAL"	= this function call is accessing kernel space memory which should never happen in ACPI.
		  ACPI is doing power management and should not alter the kernel!
		  (disclaimer: this scan method is not exact and false-possible results might happen.
		  Also, changes in further ACPI versions could redefine the tasks of ACPI.
		  Nevertheless, it is a good idea to start your investigations at these function-calls)

Example output and explanation (comments after "#"):

```
$ python vol.py --profile=LinuxUbuntu1204_3_8_0_30x86 -f ./EVIL/Ubuntu_1204_3_8_0_30-generic_EVIL.vmem scanacpitables
Volatile Systems Volatility Framework 2.3_beta

table column "Rootkit?" may have values (seems ok/unknown/suspicious/CRITICAL)
File                  Function                                                               Rootkit?   
--------------------- ---------------------------------------------------------------------- -----------
0x0009d510/DSDT.dsl   OperationRegion (IOA, SystemMemory, 0xFEC00000, 0x40)                  seems ok   #this OperationRegion seems ok, even though it is SystemMemory
0x0009d510/DSDT.dsl   OperationRegion (LA, SystemMemory, 0xFEE00000, 0x0FFF)                 seems ok   
0x0009d510/DSDT.dsl   OperationRegion (KERN, SystemMemory, 0x00100000, 0x3F8DB23F)           CRITICAL   #critical, this is the kernel space
0x0009d510/DSDT.dsl   OperationRegion (SEAC, SystemMemory, 0x00C04048, One)                  CRITICAL   
0x0009d510/DSDT.dsl   OperationRegion (NISC, SystemMemory, 0x0012BAE0, 0x40)                 CRITICAL   
0x0009d510/DSDT.dsl   OperationRegion (SAC, SystemMemory, 0x00175C96, 0x0C)                  CRITICAL   
0x0009d510/DSDT.dsl   OperationRegion (OEMD, SystemMemory, 0x3FEFFE5D, 0x60)                 seems ok   
0x0009d510/DSDT.dsl   OperationRegion (REGS, PCI_Config, 0x50, 0x30)                         seems ok   #PCI seems ok, no manipulation of kernel
0x0009d510/DSDT.dsl   OperationRegion (RE00, PCI_Config, 0xD8, 0x04)                         seems ok   
0x0009d510/DSDT.dsl   OperationRegion (PIRX, PCI_Config, 0x60, 0x04)                         seems ok   
0x0009d510/DSDT.dsl   OperationRegion (PCI, PCI_Config, 0x40, 0x60)                          seems ok   
WARNING : volatility.plugins.scanACPITables: 		      function-address 'MBAS (Arg0)' can not be evaluated
0x0009d510/DSDT.dsl   OperationRegion (MREG, SystemMemory, MBAS (Arg0), 0x10)                suspicious #MBAS is a self-defined function and can not be evaluated, this is strange
0x0009d510/DSDT.dsl   OperationRegion (EICH, SystemMemory, Add (ECFG, 0x4000), 0x4000)       seems ok   #function Add is known and therefore evaluated, ECFG is extracted too, call is checked against kernel space and seems ok
0x0009d510/DSDT.dsl   OperationRegion (SPRT, SystemMemory, Add (ECFG, Arg1), 0x04)           unknown    #Arg1 is a parameter and can not be evaluated in an offline memory image analysis
0x0009d510/DSDT.dsl   OperationRegion (SIOR, SystemIO, 0x2E, 0x02)                           seems ok   #SystemIO seems ok, like PCI
0x0009d510/DSDT.dsl   OperationRegion (LPCS, SystemMemory, ECFG, 0x0500)                     seems ok   
		      		      	     		   	 			     	   	#NEWLINE!
0x000f6b80/DSDT.dsl   OperationRegion (OEMD, SystemMemory, 0x3FEFFE5D, 0x00000060)           seems ok   #new file! (also indicated by newline in the line before)
0x000f6b80/DSDT.dsl   OperationRegion (REGS, PCI_Config, 0x50, 0x30)                         seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (RE00, PCI_Config, 0xD8, 0x04)                         seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (PIRX, PCI_Config, 0x60, 0x04)                         seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (PCI, PCI_Config, 0x40, 0x60)                          seems ok   
WARNING : volatility.plugins.scanACPITables: 		      function-address 'MBAS (Arg0)' can not be evaluated
0x000f6b80/DSDT.dsl   OperationRegion (MREG, SystemMemory, MBAS (Arg0), 0x10)                suspicious #MBAS like above
0x000f6b80/DSDT.dsl   OperationRegion (EICH, SystemMemory, Add (ECFG, 0x4000), 0x4000)       seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (SPRT, SystemMemory, Add (ECFG, Arg1), 0x04)           unknown    #Arg1 like above
0x000f6b80/DSDT.dsl   OperationRegion (SIOR, SystemIO, 0x2E, 0x02)                           seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (EREG, SystemMemory, ECFG, 0x4000)                     seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (CREG, SystemMemory, Local1, 0x10)                     unknown    #Local1 is like Arg1, can not be evaluated here
0x000f6b80/DSDT.dsl   OperationRegion (CREG, SystemMemory, Local1, 0x01)                     unknown    
0x000f6b80/DSDT.dsl   OperationRegion (RE01, PCI_Config, 0x40, 0x04)                         seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (RE02, PCI_Config, 0xC4, 0x04)                         seems ok   
0x000f6b80/DSDT.dsl   OperationRegion (REGS, PCI_Config, 0x00, 0x04)                         seems ok   
0x000f6b80/DSDT.dsl   Name (_HID, EisaId ("PNP0303"))                                        suspicious #two keyboard devices seem strange!
0x000f6b80/DSDT.dsl   Name (_HID, EisaId ("PNP0303"))                                        suspicious #seems identical but is another line
0x000f6b80/DSDT.dsl   OperationRegion (LPCS, SystemMemory, ECFG, 0x0500)                     seems ok
```


------------------------------------------------

# 4. Remarks
## 4.1 iasl

The aml-files can be decompiled into .dsl files with iasl, an official tool from ACPICA
(could be found in the Fedora/Ubuntu repositories as 'acpica-tools' - date 2020-05-02):

```$ iasl -d <file.aml>```
e.g.
```$ iasl -d ./dumpedTables/0x*/*.aml```

The resulting <file.dsl> can be opened with a normal text-editor or scanned with
the second plugin scanACPITables.py

## 4.2 ACPIstructs.py

This file includes ACPI header structs to parse the ACPI tables.
It can not be run separately but could be included in further modules which
deal with the ACPI tables.

It is needed for dumpACPITables.py and scanACPITables.py

