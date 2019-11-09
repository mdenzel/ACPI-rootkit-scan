"""
@author:	Michael Denzel
@license:	GNU General Public License 2.0 or later
"""

#imports
#volatility
import volatility.obj as obj

#XXX: Info: <VOLATILITY-struct>.d() dumps the whole structure, so e.g. RSDP.d()

# ----- class for Root System Description Pointer -----
acpi_types = {
    '_RSDP_': [ None, {
            #name, offset, type
            'Signature':	[0x00, ['String', dict(length = 8)]],
            'Checksum':		[0x08, ['unsigned char']],
            'OEMID':		[0x09, ['String', dict(length = 6)]],
            'Revision':		[0x0F, ['unsigned char']],
            'RsdtAddress':	[0x10, ['unsigned int']],
            #new members in ACPI >2.0:
            'Length':		[0x14, ['unsigned int']],
            'XsdtAddress':	[0x18, ['unsigned long long']],
            'ExtendedChecksum':	[0x20, ['unsigned char']],
            'reserved':		[0x21, ['unsigned char'], dict(length = 3)],
            }],
}
class _RSDP_(obj.CType):
    """Class for accessing the Root System Description Pointer."""

    #struct values are automatically there and can be accessed over
    #the names defined in list "acpi_types" above

    # --- additional functions ---

    #ACPI 1.0: add up every byte => result lowest byte should be 0
    #ACPI 2.0: same & do it again for rest of the bytes
    def validate(self):
        #checksum
        sum = 0
        #checksum ACPI 1.0: add up bytes
        for offset in range(0, 20):
            sum += ord(self.obj_vm.read(self.v() + offset, 1)[0])

        #lowest byte should be zero
        if((sum & 0xFF) != 0):
            return False

        #ACPI version higher than 1.0?
        if(self.Revision != 0):
            #then check rest too
            sum = 0
            for offset in range(20, 36):
                sum += ord(self.obj_vm.read(self.v() + offset, 1)[0])

            #lowest byte should be zero
            if((sum & 0xFF) != 0):
                return False

        #checksum correct...
        return True

    def check_length(self):
        if(self.Revision == 0):
            #ACPI v. 1.0
            #no length field!
            return True
        else:
            #RSDP (header-) struct size is 36 bytes,
            #so if it is not 36 then sth is included and we should check it
            if(self.Length == 0x24):
                return True
            else:
                return False

    def dump(self, outfile):
        if(self.Revision == 0):
            #ACPI v. 1.0
            for offset in range(0, 0x14):
                outfile.write(chr(ord(self.obj_vm.read(self.v() + offset, 1)[0])))
        else:
            #iterate over addr and dump to outfile
            for offset in range(0, self.Length):
                outfile.write(chr(ord(self.obj_vm.read(self.v() + offset, 1)[0])))

# ----- class for Root System Description Table -----
acpi_types.update(
    {
        #basis of all ACPI SDT
        '_ACPI_SDT_Header': [ None, {
                'Signature':		[0x00, ['String', dict(length = 4)]],
                'Length':		[0x04, ['unsigned int']],
                'Revision':		[0x08, ['unsigned char']],
                'Checksum':		[0x09, ['unsigned char']],
                'OEMID':		[0x0A, ['unsigned char', dict(length = 6)]],
                'OEMTableID':		[0x10, ['unsigned char', dict(length = 8)]],
                'OEMRevision':		[0x18, ['unsigned int']],
                'CreatorID':		[0x1C, ['unsigned int']],
                'CreatorRevision':	[0x20, ['unsigned int']],
                }],
        
        #ACPI  1.0 => RSDT
        #ACPI >2.0 => XSDT
        #attention: PointerToOtherSDT is an array of pointer of ACPI_SDT_Headers NOT a pointer to an array!
        '_RSDT_': [ None, {
                'header':		[0x00, ['_ACPI_SDT_Header']],
                'PointerToOtherSDT':	[0x24, ['array',
                                                #size: (h.Length - sizeof(h)) / 4
                                                lambda x: (x.header.Length - 0x24) / 4,
                                                ['unsigned int', ['_ACPI_SDT_Header']] #attention: "pointer" can be 64bit, but RSDT always includes 32bit pointer!
                                                ]]
                }],
        '_XSDT_': [ None, {
                'header':		[0x00, ['_ACPI_SDT_Header']],
                'PointerToOtherSDT':	[0x24, ['array',
                                                #size: (h.Length - sizeof(h)) / 8
                                                lambda x: (x.header.Length - 0x24) / 8,
                                                ['acpi_pointer64', ['_ACPI_SDT_Header']]
                                                ]]
                }],
        }
    )
class _ACPI_SDT_Header(obj.CType):
    """Class for accessing the SDT Tables."""
    #members by dict above

    def validate(self):
        sum = 0
        #checksum: add up bytes
        for offset in range(0, self.Length):
            sum += ord(self.obj_vm.read(self.v() + offset, 1)[0])

        #checksum should be zero in the lower bytes
        return (sum & 0xFF) == 0

    def dump(self, outfile):
        #iterate over addr and dump to outfile
        for offset in range(0, self.Length):
            outfile.write(chr(ord(self.obj_vm.read(self.v() + offset, 1)[0])))

class _RSDT_(obj.CType):
    """Class for accessing the Root System Description Table."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def dump(self, outfile):
        return self.header.dump(outfile)

class _XSDT_(obj.CType):
    """Class for accessing the Root System Description Table (64 bit)."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def dump(self, outfile):
        return self.header.dump(outfile)

# ----- class for Fixed ACPI Description Table -----
acpi_types.update({
        '_FADT_': [ None, {
                'header':				[0x00, ['_ACPI_SDT_Header']],
                #FACS Firmware ACPI Control Structure:
                'FirmwareControl':			[0x24, ['unsigned int']],
                #DSDT Differentiated System Description Table
                'Dsdt':					[0x28, ['unsigned int']],

                'Reserved':				[0x2C, ['unsigned char']],
                'PreferredPowerManagementProfile':	[0x2D, ['unsigned char']],
                # 0 Unspecified
                # 1 Desktop
                # 2 Mobile
                # 3 Workstation
                # 4 Enterprise Server
                # 5 SOHO Server
                # 6 Appliance PC
                # 7 Performance Server
                # 8 Tablet
                # >8 reserved


                'SCI_Interrupt':			[0x2E, ['unsigned short']],
                'SMI_CommandPort':			[0x30, ['unsigned int']],
                'AcpiEngable':				[0x34, ['unsigned char']],
                'AcpiDisable':				[0x35, ['unsigned char']],
                'S4BIOS_REQ':				[0x36, ['unsigned char']],
                'PSTATE_Control':			[0x37, ['unsigned char']],

                'PM1aEventBlock':			[0x38, ['unsigned int']],
                'PM1bEventBlock':			[0x3C, ['unsigned int']],
                'PM1aControlBlock':			[0x40, ['unsigned int']],
                'PM1bControlBlock':			[0x44, ['unsigned int']],
                'PM2ControlBlock':			[0x48, ['unsigned int']],
                'PMTimerBlock':				[0x4C, ['unsigned int']],
                'GPE0Block':				[0x50, ['unsigned int']],
                'GPE1Block':				[0x54, ['unsigned int']],

                'PM1EventLength':			[0x58, ['unsigned char']],
                'PM1ControlLength':			[0x59, ['unsigned char']],
                'PM2ControlLength':			[0x5A, ['unsigned char']],
                'PMTimerLength':			[0x5B, ['unsigned char']],
                'GPE0Length':				[0x5C, ['unsigned char']],
                'GPE1Length':				[0x5D, ['unsigned char']],
                'GPE1Base':				[0x5E, ['unsigned char']],

                'CStateControl':			[0x5F, ['unsigned char']],
                'WorstC2Latency':			[0x60, ['unsigned short']],
                'WorstC3Latency':			[0x62, ['unsigned short']],
                'FlushSize':				[0x64, ['unsigned short']],
                'FlushStride':				[0x66, ['unsigned short']],
                'DutyOffset':				[0x68, ['unsigned char']],
                'DutyWidth':				[0x69, ['unsigned char']],

                #Alarm Date?
                'DayAlarm':				[0x6A, ['unsigned char']],
                'MonthAlarm':				[0x6B, ['unsigned char']],
                'Century':				[0x6C, ['unsigned char']],

                'BootArchitectureFlags':		[0x6D, ['unsigned short']],
                'Reserved2':				[0x6F, ['unsigned char']],
                'Flags':				[0x70, ['unsigned int']],

                'ResetReg':				[0x74, ['GenericAddressStructure']],

                'ResetValue':				[0x80, ['unsigned char']],
                'Reserved3':				[0x81, ['unsigned char'], dict(length = 3)],

                #64bit version of pointers!!! available on ACPI 2.0+
                'X_FirmwareControl':			[0x84, ['acpi_pointer64']],
                'X_Dsdt':				[0x8C, ['acpi_pointer64']],
                
                'X_PM1aEventBlock':			[0x94, ['GenericAddressStructure']],
                'X_PM1bEventBlock':			[0xA0, ['GenericAddressStructure']],
                'X_PM1aControlBlock':			[0xAC, ['GenericAddressStructure']],
                'X_PM1bControlBlock':			[0xB8, ['GenericAddressStructure']],
                'X_PM2ControlBlock':			[0xC4, ['GenericAddressStructure']],
                'X_PMTimerBlock':			[0xD0, ['GenericAddressStructure']],
                'X_GPE0Block':				[0xDC, ['GenericAddressStructure']],
                'X_GPE1Block':				[0xE8, ['GenericAddressStructure']],
                }],

        #Generic Address Structure (GAS)
        'GenericAddressStructure' : [ None, {
                'AddressSpaceID':	[0x00, ['unsigned char']],
                # 0		System Memory
                # 1		System I/O
                # 2		PCI Configuration Space
                # 3		Embedded Controller
                # 4		SMBus
                # 5 to 0x09	Reserved
                # 0x0A		Platform Communications Channel (PCC)
                # 0x0B to 0x7E	Reserved
                # 0x7F		Functional Fixed Hardware
                # 0x80 to 0xBF	Reserved
                # 0xC0 to 0xFF	OEM Defined

                'RegisterBitWidth':	[0x01, ['unsigned char']],
                'RegisterBitOffset':	[0x02, ['unsigned char']],
                'AccessSize':		[0x03, ['unsigned char']],
                'Address':		[0x04, ['acpi_pointer64']],
                }],
})
class _FADT_(obj.CType):
    """Class for accessing the Fixed ACPI Description Table."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def getPreferredPowerManagementProfile(self):
        if(self.PreferredPowerManagementProfile == 0):
            return 'Unspecified'
        elif(self.PreferredPowerManagementProfile == 1):
            return 'Desktop'
        elif(self.PreferredPowerManagementProfile == 2):
            return 'Mobile'
        elif(self.PreferredPowerManagementProfile == 3):
            return 'Workstation'
        elif(self.PreferredPowerManagementProfile == 4):
            return 'Enterprise Server'
        elif(self.PreferredPowerManagementProfile == 5):
            return 'SOHO Server'
        elif(self.PreferredPowerManagementProfile == 6):
            return 'Appliance PC'
        elif(self.PreferredPowerManagementProfile == 7):
            return 'Performance Server'
        elif(self.PreferredPowerManagementProfile == 8):
            return 'Tablet'
        else:
            return 'reserved'

# ----- class for Differentiated/Secondary System Description Table -----
acpi_types.update({
        '_DSDT_': [ None, {
                'header':		[0x00, ['_ACPI_SDT_Header']],
                'DefinitionBlock':	[0x24, ['array',
                                                #size: (h.Length - sizeof(h))
                                                lambda x: (x.header.Length - 0x24),
                                                ['unsigned char']
                                                ]],
                }],

        '_SSDT_': [ None, {
                'header':		[0x00, ['_ACPI_SDT_Header']],
                'DefinitionBlock':	[0x24, ['array',
                                                #size: (h.Length - sizeof(h))
                                                lambda x: (x.header.Length - 0x24),
                                                ['unsigned char']
                                                ]],
                }]
})
class _DSDT_(obj.CType):
    """Class for accessing the Differentiated System Description Table."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def dump(self, outfile):
        return self.header.dump(outfile)

class _SSDT_(obj.CType):
    """Class for accessing the Differentiated System Description Table."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def dump(self, outfile):
        return self.header.dump(outfile)

# ----- helper class for Type-Length-Headers (like in MADT, SRAT...)  -----
acpi_types.update({
        '_TypeLength_Header': [ None, {
                'Type':		[0x00, ['unsigned char']],
                'Length':	[0x01, ['unsigned char']],
                }],
})

class _TypeLength_Header(obj.CType):
    """Helper class for accessing the Type-Length-Headers."""

# ----- class for Multiple APIC Description Table -----
acpi_types.update({
        #problem with size, therefore extra type
        '_IC_helper': [ None, {
                'TL_header':	[0x00, ['_TypeLength_Header']],

                #size of data varies, but has to be computed here
                #to create the array below in MADT
                'Data':		[0x02, ['array',
                                        #size: _InterruptController_Header.Length
                                        lambda x: (x.TL_header.Length - 0x02),
                                        ['unsigned char']
                                        ]
                                 ],
                }],

        '_IO_APIC_Structure': [ None, {
                'TL_header':		[0x00, ['_TypeLength_Header']],
                'IO_APIC_ID':		[0x02, ['unsigned char']],
                'Reserved':		[0x03, ['unsigned char']],
                'IO_APIC_Address':	[0x04, ['unsigned int']],
                'GSI_Base':		[0x08, ['unsigned int']],
                }],

        '_MADT_': [ None, {
                'header':				[0x00, ['_ACPI_SDT_Header']],
                'LocalInterruptControllerAddress':	[0x24, ['unsigned int']],
                'Flags':				[0x28, ['unsigned int']],
                'InterruptControllerStructure':		[0x2C, ['unsigned int']], #later used in combination with IC_header
                }],
})

class _MADT_(obj.CType):
    """Class for accessing the Multiple APIC Description Table."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def dump(self, outfile):
        return self.header.dump(outfile)

class _IC_helper(obj.CType):
    """Helper class for accessing the Multiple APIC Description Table."""

    #validate that header has right length
    def validate(self):
        if(self.TL_header.Type == 0 and self.TL_header.Length == 8):
            return True
        elif(self.TL_header.Type == 1 and self.TL_header.Length == 12):
            return True
        elif(self.TL_header.Type == 2 and self.TL_header.Length == 10):
            return True
        elif(self.TL_header.Type == 3 and self.TL_header.Length == 8):
            return True
        elif(self.TL_header.Type == 4 and self.TL_header.Length == 6):
            return True
        elif(self.TL_header.Type == 5 and self.TL_header.Length == 12):
            return True
        elif(self.TL_header.Type == 6 and self.TL_header.Length == 16):
            return True
        #minimum 17
        elif(self.TL_header.Type == 7 and self.TL_header.Length >= 17):
            return True
        elif(self.TL_header.Type == 8 and self.TL_header.Length == 16):
            return True
        elif(self.TL_header.Type == 9 and self.TL_header.Length == 16):
            return True
        elif(self.TL_header.Type == 0xA and self.TL_header.Length == 12):
            return True
        elif(self.TL_header.Type == 0xB and self.TL_header.Length == 40):
            return True
        elif(self.TL_header.Type == 0xC and self.TL_header.Length == 24):
            return True
        #minimum = Type + Length
        elif(self.TL_header.Type >= 0xD and self.TL_header.Type <= 0x7F and self.TL_header.Length >= 2):
            return True
        #minimum = Type + Length
        elif(self.TL_header.Type >= 0x80 and self.TL_header.Length >= 2):
            return True
        else:
            return False

    #get written name of the type
    def getTypeAsString(self):
        if(self.TL_header.Type == 0):
            return "Processor Local APIC"
        elif(self.TL_header.Type == 1):
            return "I/O APIC"
        elif(self.TL_header.Type == 2):
            return "Interrupt Source Override"
        elif(self.TL_header.Type == 3):
            return "Non-maskable Interrupt Source (NMI)"
        elif(self.TL_header.Type == 4):
            return "Local APIC NMI"
        elif(self.TL_header.Type == 5):
            return "Local APIC Address Override"
        elif(self.TL_header.Type == 6):
            return "I/O SAPIC"
        elif(self.TL_header.Type == 7):
            return "Local SAPIC"
        elif(self.TL_header.Type == 8):
            return "Platform Interrupt Sources"
        elif(self.TL_header.Type == 9):
            return "Processor Local x2APIC"
        elif(self.TL_header.Type == 0xA):
            return "Local x2APIC NMI"
        elif(self.TL_header.Type == 0xB):
            return "GIC"
        elif(self.TL_header.Type == 0xC):
            return "GICD"
        elif(self.TL_header.Type >= 0xD and self.TL_header.Type <= 0x7F):
            return "Reserved"
        elif(self.TL_header.Type >= 0x80 and self.TL_header.Type <= 0xFF):
            return "Reserved for OEM use"
        else:
            #for errors (maybe value will be expanded?)
            return "unknown"

class _IO_APIC_Structure(obj.CType):
    """Class for accessing the IO APIC in the Multiple APIC Description Table."""

    def validate(self):
        return self.TL_header.validate()

    def getTypeAsString(self):
        return self.TL_header.getTypeAsString()

# ----- class for System Resource Affinity Table -----
acpi_types.update({
        #IC_Header has different Types therefore cannot be reused
        #problem with size, therefore extra type
        '_RA_helper': [ None, {
                'TL_header':	[0x00, ['_TypeLength_Header']],

                #size of data varies, but has to be computed here
                #to create the array below in SRAT
                'Data':		[0x02, ['array',
                                        #size: header.Length
                                        lambda x: (x.TL_header.Length - 0x02),
                                        ['unsigned char']
                                        ]
                                 ],
                }],

        '_Memory_Affinity_Structure': [ None, {
                'TL_header':		[0x00, ['_TypeLength_Header']],
                'Proximity_Domain':	[0x02, ['unsigned int']],
                'Reserved':		[0x06, ['unsigned short']],
                'Base_Address_Low':	[0x08, ['unsigned int']],
                'Base_Address_High':	[0x0C, ['unsigned int']],
                'Length_Low':		[0x10, ['unsigned int']],
                'Length_High':		[0x14, ['unsigned int']],
                'Reserved2':		[0x18, ['unsigned int']],
                'Flags':		[0x1C, ['unsigned int']],
                'Reserved3':		[0x20, ['unsigned long long']],
                }],

        '_SRAT_': [ None, {
                'header':	[0x00, ['_ACPI_SDT_Header']],
                'Reserved':	[0x24, ['unsigned char'], dict(length = 12)],
                'StaticResourceAllocationStructure':
                    [0x30, ['unsigned int']], #later used in combination with IC_header
                }],
})

class _SRAT_(obj.CType):
    """Class for accessing the System Resource Affinity Table."""
    #members by dict above

    def validate(self):
        #check header
        return self.header.validate()

    def dump(self, outfile):
        return self.header.dump(outfile)

class _RA_helper(obj.CType):
    """Helper class for accessing the System Resource Affinity Table."""
        
    #validate that header has right length
    def validate(self):
        if(self.TL_header.Type == 0 and self.TL_header.Length == 16):
            return True
        elif(self.TL_header.Type == 1 and self.TL_header.Length == 40):
            return True
        elif(self.TL_header.Type == 2 and self.TL_header.Length == 24):
            return True
        else:
            return False

    #get written name of the type
    def getTypeAsString(self):
        if(self.TL_header.Type == 0):
            return "Processor Local APIC/SAPIC Affinity Structure"
        elif(self.TL_header.Type == 1):
            return "Memory Affinity Structure"
        elif(self.TL_header.Type == 2):
            return "Processor Local 2xAPIC Affinity Structure"
        else:
            #for errors (maybe value will be expanded?)
            return "unknown"

class _Memory_Affinity_Structure(obj.CType):
    """Class for accessing the memory structure of SRAT."""

    def validate(self):
        #check header
        if(self.TL_header.Type == 1 and self.TL_header.Length == 40):
            return True
        else:
            return False

    def getBase(self):
        return (self.Base_Address_High << 32) | self.Base_Address_Low

    def getLength(self):
        return (self.Length_High << 32) | self.Length_Low

# ----- adding RSDP, RSDT etc. to volatility -----
class ACPIObjectClasses(obj.ProfileModification):
    #modifications that should be before this class
    before = ['WindowsOverlay', 'WindowsVTypes', 'WindowsObjectClasses', 'LinuxObjectClasses']
    conditions = {'os': lambda x: x == 'windows' or x == 'linux'}
    
    def modification(self, profile):
        #pointer64 does not exist, create it as 8byte value
        # q   A signed quad (64-bit) value
        # Q   An unsigned quad value
        # < stands for "non-be" value (assumption: be = big endian)
        profile.native_types.update({'acpi_pointer64': [8, '<Q']})

        profile.vtypes.update(acpi_types)
        profile.object_classes.update({
                #entry point ACPI tables
                '_RSDP_': _RSDP_,
                #SDT in general
                '_ACPI_SDT_Header': _ACPI_SDT_Header,
                #all tables
                '_RSDT_': _RSDT_,
                '_XSDT_': _XSDT_,
                '_FADT_': _FADT_,
                '_DSDT_': _DSDT_,
                '_SSDT_': _SSDT_,

                #helper for MADT, SRAT...
                '_TypeLength_Header' : _TypeLength_Header,

                #MADT (includes a list => problematic)
                '_IC_helper' : _IC_helper, #helper for MADT
                '_IO_APIC_Structure' : _IO_APIC_Structure,
                '_MADT_': _MADT_,

                #SRAT (same principle as MADT)
                '_RA_helper': _RA_helper,
                '_Memory_Affinity_Structure': _Memory_Affinity_Structure,
                '_SRAT_': _SRAT_,
                })
#EOF
