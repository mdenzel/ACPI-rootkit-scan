"""
@author:	Michael Denzel
@license:	GNU General Public License 2.0 or later
"""

#imports
#volatility
import volatility.plugins.common as common
import volatility.plugins.linux.common as linux_common
import volatility.utils as utils
import volatility.scan as scan
import volatility.obj as obj
import volatility.debug as debug
#python
import os as os
#own modules
import ACPIstructs

# ----- scanner class for Root System Description Pointer -----
class RSDPcheck(scan.ScannerCheck):
    """Check for ACPI tables identifier"""

    def __init__(self, address_space, tag = None, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.tag = tag

    def check(self, offset):
        data = self.address_space.read(offset, len(self.tag))
        return data == self.tag

class RSDPscan(scan.BaseScanner):
    """Scanning for ACPI tables identifier"""

    checks = [] #checks are in volatility/plugins/common.py

    def __init__(self):
        scan.BaseScanner.__init__(self)
        #identify the RSDP, magic byte "RSD PTR "
        #with space at the end, 8 bytes!
        self.checks = [('RSDPcheck', dict(tag = "RSD PTR "))]

# ----- main class -----
class dumpACPITables(common.AbstractWindowsCommand, linux_common.AbstractLinuxCommand):
    """Dump ACPI Tables in raw/aml format."""
    
    # ----- constructor -----
    def __init__(self, config, *args, **kwargs):
        #setup
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

        # --- CONFIG ---
        #constants
        #suffixes, dont forget the "." in front!
        self.SUFFIX = ".raw"
        self.AML = ".aml"

        #parameters
        self._config.add_option('CONTINUE_ON_CHECKSUM_FAIL', short_option = 'c', default = False,
                                help = 'Continue to dump this table on checksum fail (instead of going to next base-pointer). ' + 
                                'Try to dump it and go on with it\'s sub-tables, ' +
                                'not matter what (attention: this option might crash the program!).',
                                action = 'store_true')
        self._config.add_option('ALWAYS_DUMP_RSDT', short_option = 'a', default = False,
                                help = "Dump ACPI Tables v. 1.0 even if a higher version exists.", action = 'store_true')
        self._config.add_option('JUST_PRINT_RSDP', short_option = 'j', default = False,
                                help = 'Just print base pointers RSDP without dumping the tables to files. (ignores all input options except START/END)',
                                action = 'store_true')
        self._config.add_option('PATH', short_option = 'p', default = './dumpedTables',
                                help = 'Path to folder to dump the ACPI tables.',
                                action = 'store', type = 'str')
        self._config.add_option('START', short_option = 's', default = None,
                                help = 'Start of the scan for base pointer RSDP.\n' + 
                                'Otherwise: scan for base pointer RSDP where it should be' + 
                                ' (= 0x00080000 to 0x000A0000 and 0x000E0000 to 0x00100000).',
                                action = 'store', type = 'int')
        self._config.add_option('END', short_option = 'e', default = None,
                                help = 'End of the scan for base pointer RSDP', action = 'store', type = 'int')
        self._config.add_option('OVERWRITE', short_option = 'o', default = False,
                                help = 'Overwrite existing files in PATH (option -p).',
                                action = 'store_true')
        # --------------

        #variables
        self.physical_address_space = None
        self.kernel_address_space = None

        #check if "path" exists
        if(not os.path.isdir(self._config.PATH)):
            os.makedirs(self._config.PATH)

    # ----- helpers -----

    #dump every SDT table    
    def dump_table(self, folder, SDT, filename):
        #init
        outfile = "{0}/{1}".format(
            folder,
            filename
            )

        #check if file exists
        if(os.path.isfile(outfile) and not self._config.OVERWRITE):
            debug.warning("file {0} already exists - skip".format(outfile))
            return

        #dump table to file
        fobj = open(outfile, "wb") #open in byte-mode!
        SDT.dump(fobj)
        fobj.close()

    #----------------------- end def -----------------------

    #dump all tables under a certain RSDP
    def dump_tables_at(self, RSDPaddr):
        #find RSDP
        RSDP = obj.Object("_RSDP_",
                          offset=RSDPaddr,
                          vm=self.physical_address_space,
                          native_vm=self.kernel_address_space
                          )
        
        #checks (no continue because this is our entry point)
        if(RSDP == None):
            debug.warning("RSDP is None!")
            debug.warning("next RSDP")
            return None
        elif(RSDP.size() == 0):
            debug.warning("RSDP size is 0!")
            debug.warning("next RSDP")
            return None
        #validate structure
        elif(RSDP.Signature != "RSD PTR "):
            debug.warning("RSDP signature not valid")
            debug.warning("next RSDP")
            return None
        if(not RSDP.validate()):
            debug.warning("RSDP checksum not valid")
            if(not self._config.CONTINUE_ON_CHECKSUM_FAIL):
                debug.warning("next RSDP")
                return None
        #RSDP should not have a body => fail if so?
        if(not RSDP.check_length()):
            debug.warning("RSDP table wrong length: {0} (should be 36)".format(RSDP.Length))
            if(not self._config.CONTINUE_ON_CHECKSUM_FAIL):
                debug.warning("next RSDP")
                return None
        #end checks

        #folder to dump tables is the addr of base-pointer RSDP (there might be more RSDPs in memory!)
        folder = "{0}/0x{1:08x}".format(self._config.PATH, RSDPaddr)
        if(not os.path.isdir(folder)):
            os.makedirs(folder)
        #endif

        #dump RSDP
        self.dump_table(folder, RSDP, "RSDP" + self.SUFFIX)

        #ACPI version higher than 1.0?
        #ACPI counts from 0!
        RSDT = None
        if(RSDP.Revision > 0 and not self._config.ALWAYS_DUMP_RSDT):

            #get XSDT out of RSDP
            RSDT = obj.Object("_XSDT_", offset=RSDP.XsdtAddress,
                              vm=self.physical_address_space, native_vm=self.kernel_address_space)
            if(RSDT == None):
                debug.warning("Cannot access XSDT at 0x{0:08x}".format(RSDP.XsdtAddress))
                debug.warning("next RSDP")
                return (RSDP.Revision + 1, RSDP.RsdtAddress, RSDP.XsdtAddress, None)

            #check
            if(RSDT.header.Signature != "XSDT"):
                debug.warning("XSDT signature not valid: '{0}'".format(RSDT.header.Signature))
                if(not self._config.CONTINUE_ON_CHECKSUM_FAIL):
                    debug.warning("next RSDP")
                    return (RSDP.Revision + 1, RSDP.RsdtAddress, RSDP.XsdtAddress, None)
            #endif
        else:
            #get RSDT out of RSDP
            RSDT = obj.Object("_RSDT_", offset=RSDP.RsdtAddress,
                              vm=self.physical_address_space, native_vm=self.kernel_address_space)
            if(RSDT == None):
                debug.warning("Cannot access RSDT at 0x{0:08x}".format(RSDP.RsdtAddress))
                debug.warning("next RSDP")
                return (RSDP.Revision + 1, RSDP.RsdtAddress, 0, None)

            #check
            if(RSDT.header.Signature != "RSDT"):
                debug.warning("RSDT signature not valid: '{0}'".format(RSDT.header.Signature))
                if(not self._config.CONTINUE_ON_CHECKSUM_FAIL):
                    debug.warning("next RSDP")
                    return (RSDP.Revision + 1, RSDP.RsdtAddress, 0, None)
                #endif
            #endif
        #endif

        if(not RSDT.validate()):
            debug.warning("RSDT/XSDT checksum not valid")
            if(not self._config.CONTINUE_ON_CHECKSUM_FAIL):
                debug.warning("next RSDP")
                #tell that RSDP was dumped
                if(RSDP.Revision == 0):
                    return (RSDP.Revision + 1, RSDP.RsdtAddress, 0, None)
                else:
                    return (RSDP.Revision + 1, RSDP.RsdtAddress, RSDP.XsdtAddress, None)
            #endif
        #endif

        #dump RSDT/XSDT
        self.dump_table(folder, RSDT, RSDT.header.Signature + self.SUFFIX)

        #iterate over all included tables
        ret = list() #return value
        ret.append((0, 0, RSDT.header.Signature))
        num_ssdt = 0 #for counting the SSDTs
        FADT = None
        for i, sdt_offset in enumerate(RSDT.PointerToOtherSDT):
            #get all SDTs of RSDT/XSDT
            SDT = obj.Object("_ACPI_SDT_Header", offset=sdt_offset,
                             vm=self.physical_address_space, native_vm=self.kernel_address_space)

            #check
            if(SDT == None):
                debug.warning("SDT no. {0} at 0x{1:08x} can not be parsed.".format(i, sdt_offset))
                continue
            if(not SDT.Signature):
                #empty string!
                debug.warning("SDT at 0x{0:08x} has an empty signature!".format(sdt_offset))
                continue
            if(not SDT.validate()):
                debug.warning("Checksum of {0} at 0x{1:08X} failed".format(SDT.Signature, SDT.v()))
                if(not self._config.CONTINUE_ON_CHECKSUM_FAIL):
                    #goto next SDT if checksum fail
                    continue

            #ACPI 1.0 => 32 bit, else 64 bit pointer
            if(RSDP.Revision > 0 and not self._config.ALWAYS_DUMP_RSDT):
                #index, maxindex, signature
                ret.append((i+1, (RSDT.header.Length - 0x24) / 8, SDT.Signature))
            else:
                #index, maxindex, signature
                ret.append((i+1, (RSDT.header.Length - 0x24) / 4, SDT.Signature))
            #endif

            #just process needed tables
            #only DSDT (in FACP) and SSDT include AML-code
            if(SDT.Signature == "FACP"):
                #dump FACP
                self.dump_table(folder, SDT, "FADT" + self.SUFFIX)

                #FACP => look at DSDT and FACS
                #cast SDT
                FADT = SDT.cast("_FADT_")
                #no need to validate signature/checksum, already done above

                #dump DSDT
                DSDT = None
                if(RSDP.Revision > 0 and not self._config.ALWAYS_DUMP_RSDT):
                    DSDT = obj.Object("_ACPI_SDT_Header", offset=FADT.X_Dsdt,
                                      vm=self.physical_address_space,
                                      native_vm=self.kernel_address_space)
                    if(DSDT == None):
                        debug.warning("Could not read FADT.X_Dsdt, trying FADT.Dsdt")
                    #end if
                #end if

                if(DSDT == None or RSDP.Revision == 0 or self._config.ALWAYS_DUMP_RSDT):                    
                    DSDT = obj.Object("_ACPI_SDT_Header", offset=FADT.Dsdt,
                                      vm=self.physical_address_space,
                                      native_vm=self.kernel_address_space)
                #endif

                if(DSDT == None):
                    debug.warning("DSDT is None! - skipped")
                else:
                    if(DSDT.Signature != "DSDT"):
                        debug.warning("DSDT signature not valid: '{0}' - skipped".format(DSDT.Signature))
                    else:
                        self.dump_table(folder, DSDT, DSDT.Signature + self.AML)
                        ret.append((str(i+1) + "a", None, "DSDT"))
                #endif

                #dump FACS
                FACS = None
                #ACPI v. 1.0 => take FirmwareControl
                #ACPI v. >1.0 and FirmwareControl 0x0 => take X_FirmwareControl
                #ACPI v. >1.0 and FirmwareControl 0x0 and X_FirmwareControl 0x0 => take FirmwareControl
                #otherwise => error, dont know what's wrong
                if(RSDP.Revision == 0 or FADT.X_FirmwareControl == 0x0 or self._config.ALWAYS_DUMP_RSDT):
                    FACS = obj.Object("_ACPI_SDT_Header", offset=FADT.FirmwareControl,
                                      vm=self.physical_address_space,
                                      native_vm=self.kernel_address_space)
                elif(RSDP.Revision > 0 and FADT.X_FirmwareControl != 0x0 and FADT.FirmwareControl == 0):
                    FACS = obj.Object("_ACPI_SDT_Header", offset=FADT.X_FirmwareControl,
                                      vm=self.physical_address_space,
                                      native_vm=self.kernel_address_space)
                elif(RSDP.Revision > 0 and FADT.X_FirmwareControl != 0 and FADT.FirmwareControl != 0):
                    #error according to docu, but this happened quite often!
                    debug.warning("FADT.X_FirmwareControl and FADT.FirmwareControl set! " +
                                  "According to ACPI documentation this is not allowed! - Trying FirmwareControl")
                    FACS = obj.Object("_ACPI_SDT_Header", offset=FADT.FirmwareControl,
                                      vm=self.physical_address_space,
                                      native_vm=self.kernel_address_space)
                else:
                    #maybe X_FirmwareControl and FirmwareControl are not set. This should also not happen
                    debug.warning("FACS skipped, Error: ACPI v. {0}, FADT.X_FirmwareControl: 0x{1:016x}, FADT.FirmwareControl: 0x{2:08x}".format(
                            RSDP.Revision,
                            FADT.X_FirmwareControl,
                            FADT.FirmwareControl
                            ))
                    continue
                #end if

                if(FACS == None):
                    debug.warning("FACS is None! - skipped")
                else:
                    if(FACS.Signature != "FACS"):
                        debug.warning("FACS signature not valid: '{0}' - skipped".format(FACS.Signature))
                    else:
                        self.dump_table(folder, FACS, FACS.Signature + self.SUFFIX)
                        ret.append((str(i+1) + "b", None, FACS.Signature))
                #endif
            elif(SDT.Signature == "SSDT"):
                #there can be multiple SSDTs so enumerate them
                self.dump_table(folder, SDT, SDT.Signature + "_" + str(num_ssdt) + self.AML)
                num_ssdt += 1
            else:
                #any other table: dump it
                if(SDT.Signature == "APIC"):
                    self.dump_table(folder, SDT, "MADT" + self.SUFFIX)
                else:
                    self.dump_table(folder, SDT, SDT.Signature + self.SUFFIX)
                #end if
            #end if
        #end for

        #FADT is compulsory!
        if(FADT == None):
            debug.warning("FADT table is missing, even though it is compulsory!")
        #endif

        #return which tables were dumped for output
        if(RSDP.Revision == 0):
            return (RSDP.Revision + 1, RSDP.RsdtAddress, 0, ret)
        else:
            return (RSDP.Revision + 1, RSDP.RsdtAddress, RSDP.XsdtAddress, ret)

    #----------------------- end helpers -----------------------

    #validity check (optional)
    @staticmethod
    def is_valid_profile(profile):
        """Returns true if the plugin is valid for the current profile"""
        return (profile.metadata.get('os', 'unknown') == 'windows') or (profile.metadata.get('os', 'unknown') == 'linux')
    
    #----------------------- end def -----------------------

    #main method
    def calculate(self):
        #load kernel space (= virtual address space)
        self.kernel_address_space = utils.load_as(self._config)
        if(not self.is_valid_profile(self.kernel_address_space.profile)):
            debug.error("Unsupported profile: {0}".format(
                    self.kernel_address_space.profile.metadata.get('os', 'unknown')))

        #load physical address space
        self.physical_address_space = utils.load_as(self._config, astype = 'physical')
        if(not self.is_valid_profile(self.physical_address_space.profile)):
            debug.error("Unsupported profile: {0}".format(
                    self.physical_address_space.profile.metadata.get('os', 'unknown')))


        #init start and end
        start = 0
        length = 0
        #"skip" does already exist in volatility-scanner class!
        #skipStart and skipEnd have to be the same when not set!
        skipStart = skipEnd = 0
        if(self._config.START != None and
           self._config.END != None):
            
            #values for START and END overwrite default config
            start = self._config.START
            length = self._config.END - start
        elif(self._config.START == None and
             self._config.END == None):

            #no config, default values
            #search Root System Description Pointer (= start of ACPI tables)
            #located in Extended Bios Data Area (EBDA) at 0x00080000 to 0x000A0000 or
            #located between 0x000E0000 and 0x00100000 (and 16bit aligned)
            start  = 0x00080000
            length = 0x00100000 - start

            #volatility did not offer a way to get the absolut addresses
            #in a scanner.skip(...) method
            #therefore it is not possible to implement a
            #skip(...) function for this issue
            skipStart = 0x000A0000
            skipEnd   = 0x000E0000
        else:
            #error (maybe start given and no end...)
            debug.error("START and END required or none of both")
        #endif

        #MAIN SCANNING LOOP FOR RSDP
        nr = 0
        (acpiversion, rsdt, xsdt, sdtlist) = (None, None, None, None)
        for index, addr in enumerate(RSDPscan().scan(
                self.physical_address_space, start, length)):
            
            #skipper manually, see definition of skipStart/skipEnd above for reason
            if(skipStart < addr and addr < skipEnd):
                continue

            #dump tables
            if(not self._config.JUST_PRINT_RSDP):
                d = self.dump_tables_at(addr)
                if(d == None):
                    continue
                else:
                    (acpiversion, rsdt, xsdt, sdtlist) = d
            #end if

            nr += 1
            yield (nr, addr, acpiversion, rsdt, xsdt, sdtlist)
        #end for

        if(not ('index' in locals())):
            if(skipStart != skipEnd):
                debug.error("Could not find RSDP in [0x{0:08x}, 0x{1:08x}] (skipped: [0x{2:08x}, 0x{3:08x}])".format(
                        start, start+length, skipStart, skipEnd
                        ))
            else:
                debug.error("Could not find RSDP in [0x{0:08x}, 0x{1:08x}]".format(start, start+length))
            #end if
        #end if

    #----------------------- end def -----------------------

    def render_text(self, outfd, data):
        #print warning for not safe options
        if(self._config.CONTINUE_ON_CHECKSUM_FAIL):
            debug.warning("Continue on checksum fail might crash the program!")

        #table header
        if(self._config.JUST_PRINT_RSDP):
            self.table_header(outfd, [
                    ("No.", "3"), ("RSDP", "#010x") #10 with "0x" in front
                    ])
        else:
            self.table_header(outfd, [
                    ("No.", "3"), ("RSDP", "#010x"), #10 with "0x" in front
                    ("ACPI v.", "7"), ("RSDT", "#010x"),
                    ("XSDT", "#010x")
                    ])

        for (nr, addr, acpiversion, rsdt, xsdt, sdtlist) in data:
            #print RSDP as table
            if(self._config.JUST_PRINT_RSDP):
                self.table_row(outfd, nr, addr)
                continue
            else:
                self.table_row(outfd, nr, addr, acpiversion, rsdt, xsdt)
            #end if

            #print SDTs as list
            if(sdtlist != None):
                for (index, maxindex, sdtname) in sdtlist:
                    #RSDT/XSDT
                    if(index == 0 and maxindex == 0):
                        outfd.write("\t{0}:\n".format(
                                sdtname
                                ))
                    #sub-SDTs
                    elif(maxindex != None):
                        outfd.write("\tSDT {0} of {1}: {2}\n".format(
                                index, maxindex, sdtname
                                ))
                    else:
                        outfd.write("\t |-> SDT {0}: {1}\n".format(
                                index, sdtname
                                ))
                    #end if
                #end for loop
            #end if
        #end for loop

    #----------------------- end def -----------------------

#EOF
