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
from re import match #regex.match for rootkit scan
from re import findall #regex.match for rootkit scan
from re import escape #for regex
#for endianess conversion
from binascii import unhexlify
#calculations of bits in a byte-vector:
from math import ceil
from math import floor
#own modules
import volatility.plugins.dumpACPITables as dumpACPITables
import ACPIstructs

# ----- parser class to convert address-expressions into absolute values -----
class Parser:
    """Parsing address-expressions"""

    # ----- constructor -----
    def __init__(self, physical_address_space):
        self.physical_address_space = physical_address_space
        self.reset()

    def reset(self):
        self.dictionary = dict() #{id : absolute addr}
        self.OpRegionsIdentifiers = dict() #{id : value}
        self.FieldIdentifiers = dict() #{id : {offsetname : (absolute_offset_from_begining_of_field, length)}
        self.unknownIdentifiers = set() #(at the moment = DURING file-parse) unknown identifiers, should be empty at the end

    # ----- functions -----
    def update_dictionary(self):
        #do not alter set while iterating over it!
        to_delete = set()

        #update dictionary if possible
        for offsetname in self.unknownIdentifiers:
            #try to find one of the unknown identifiers
            entry = None
            key = None
            for key in self.FieldIdentifiers:
                if(offsetname in self.FieldIdentifiers[key]):
                    entry = self.FieldIdentifiers[key][offsetname]
                    break
            #found one?
            if(entry == None):
                continue

            #update
            addr = 0
            if(self.OpRegionsIdentifiers[key] != None):
                addr = int(self.OpRegionsIdentifiers[key])
            else:
                #missing OperationRegion for Field-call!
                continue

            #access to memory to get Field out of RAM!
            #entry consists of (offset_in_bits, length_in_bits)
            bytes_to_read = int(ceil(float(int(entry[0]) + int(entry[1])) / 8.0))
            value = self.physical_address_space.zread(addr, bytes_to_read) #zread to get the bits at the right positions
            if(value == None):
                debug.warning("Symbol {0} in struct at address 0x{1:08x}: read value None, skip".format(offsetname, addr))
                value = "unknown"
            else:
                #get bit position out of read bytes
                value = int(value.encode('hex'), 16)
                if(value == 0x0):
                    debug.warning("Symbol {0} in struct at address 0x{1:08x}: read value 0x0, skip".format(offsetname, addr))
                    value = "unknown"
                else:
                    #cut the values out of struct: cut bits_to_cut_back from behind and then just take entry[1] bits
                    #of the remaining byte-vector
                    bits_to_cut_back = int(bytes_to_read * 8 - (int(entry[0]) + int(entry[1])))
                    value = (value >> bits_to_cut_back) & ((1 << entry[1])-1)

                    #change endianess
                    #cast into hex bytes array
                    s = "{0:0" + str(int(ceil(float(entry[1]) / 4.0))) + "x}"
                    tmp = unhexlify(s.format(value))
                    #switch bytes
                    tmp = tmp[::-1]
                    #cast back into int
                    value = int(tmp.encode('hex'), 16)
                #end if
            #end if

            #save offsetname
            self.dictionary.update({offsetname : value})
            to_delete.add(offsetname)
        #end for
            
        #delete
        self.unknownIdentifiers.difference_update(to_delete)
    #----------------------- end def -----------------------

    def parse_Field_call(self, firstline, fobj, identifier):
        #search beginning of field-call (= first "{")
        line = firstline
        while(not match(r"{", line)):
            line = fobj.next().lstrip().rstrip()
        #end while
            
        #init
        offset = 0
        firstBracket = True
        doWhile = True
        while(doWhile):
            #check line
            if(match(r"{", line)):
                if(firstBracket):
                    firstBracket = False
                else:
                    debug.warning("Additional opening bracket \"{\" in Field-call")
                #endif
            elif(match(r"Offset.*", line)):
                tmp = findall(r"\(\s*([0x[0-9A-Fa-f]+|[0-9]+])\s*\)", line)
                if(len(tmp) != 1):
                    debug.warning("Cannot parse Offset-line in Field-call: {0} => skip this field!".format(line))
                    break
                else:
                    tmp = tmp[0]
                #endif

                #int value
                if(match(r"[1-9][0-9]*", tmp)):
                    tmp = int(tmp)
                #hex value
                elif(match(r"0x[0-9A-Fa-f]+", tmp)):
                    tmp = int(tmp, 16)
                #endif
      
                #save offset
                offset += tmp * 8 #Attention: offset is in byte according to docu, so make it to bits
            elif(match(r"\w*,\s*[0x[0-9A-Fa-f]+|[1-9][0-9]*]\s*,", line)):
                offsetname = findall(r"(\w*),\s*[0x[0-9A-Fa-f]+|[1-9][0-9]*]\s*,{0,1}", line)
                if(len(offsetname) != 1):
                    debug.warning("Cannot pass offsetname in line in Field-call: '{0}' => skip this field!".format(line))
                    break
                else:
                    offsetname = offsetname[0]
                #endif

                tmp = findall(r"\w*,\s*([0x[0-9A-Fa-f]+|[1-9][0-9]*])\s*,{0,1}", line)
                if(len(tmp) != 1):
                    debug.warning("Cannot parse offset-int in line in Field-call: '{0}' => skip this field!".format(line))
                    break
                else:
                    tmp = tmp[0]
                #endif

                #int value
                if(match(r"[1-9][0-9]*", tmp)):
                    tmp = int(tmp)                #hex value
                elif(match(r"0x[0-9A-Fa-f]+", tmp)):
                    tmp = int(tmp, 16)
                #endif

                #add offsetidentifier, it's offset and it's length
                self.FieldIdentifiers[identifier].update({offsetname : (offset, tmp)})

                #attention: update offset AFTER inserting the identifier
                offset += tmp #tmp BITS! not bytes
                #example:
                # Field(...){
                #	X, 32 //offset is 0 (not 32!), length is 32
                #	Y, 16 //offset is 32, length is 16
                # }

                self.update_dictionary() #new Field!
            elif(not (len(line) == 0 or match(r"AccessAs", line) or match(r"}", line))):
                debug.warning("Cannot parse Field-Call line: {0}".format(line))
            #end if

            #dowhile loop
            if(match(r"}", line)):
                doWhile = False

            #next
            line = fobj.next()
            line = line.lstrip().rstrip()
        #end while

    #----------------------- end def -----------------------

    #returns None if we are NOT in a Field-Call
    #or returns the identifier of the Field-Call Field(id, ...)
    def store_address(self, line):
        #check if line is useable
        if(match(r"\s*Field.*", line)):
            #get identifier out of field call, rest is not interesting
            identifier = findall(r"Field\s*\(\s*(\w*)\s*,[^,]+,[^,]+,[^,]+\).*", line) #simple string => \w
            if(len(identifier) != 1):
                debug.warning("Field-call can not be parsed: {0}".format(line))
                return False
            else:
                identifier = identifier[0]
            #end if

            #update
            self.FieldIdentifiers.update({identifier : dict()})
            self.update_dictionary() #new Field!
            return identifier
        elif(match(r".*OperationRegion.*SystemMemory.*", line)):
            #extract SystemMemory identifier/value pairs
            identifier = findall(r"OperationRegion\s*\(\s*(\w*)\s*,\s*SystemMemory\s*,[^,]+,[^,]+\).*", line) #simple string => \w
            if(len(identifier) != 1):
                debug.warning("OperationRegion can not be parsed: {0}".format(line))
                return False
            else:
                identifier = identifier[0]
            #endif
            
            #value can be also a complex expression => . instead of \w
            value = findall(r"OperationRegion\s*\([^,]+,\s*SystemMemory\s*,\s*(.*)\s*,[^,]+\).*", line)
            if(len(value) != 1):
                debug.warning("OperationRegion can not be parsed: {0}".format(line))
                return False
            else:
                value = value[0]
            #endif

            #int value
            if(match(r"[1-9][0-9]*", value)):
                value = int(value)
            #hex value
            elif(match(r"0x[0-9A-Fa-f]+", value)):
                value = int(value, 16)
            #endif

            self.OpRegionsIdentifiers.update({identifier : value})
            self.update_dictionary() #new OpRegion
            return False
        else:
            #unuseable line
            return False
        #end if(<functionname>)

    #----------------------- end def -----------------------

    #parse a given id into it's absolute value
    def parse(self, addr_in):
        addr = addr_in.lstrip().rstrip()

        #int value
        if(match(r"[1-9][0-9]*", addr)):
            return int(addr)
        #hex value
        elif(match(r"0x[0-9A-Fa-f]+", addr)):
            return int(addr, 16)
        #local variables (Local0-7) or arguments (Arg0-6) can not be tracked
        #e.g. Arg0-Arg6 are from function calls, this can not be evaluated on dead analysis!
        elif(match(r"Local[0-7]|Arg[0-6]", addr)):
            return "unknown"
        #identifier = "FieldUnitName" (1 to 4 characters) p. 752 acpi docu
        elif(match(r"\A\w{4}\Z", addr)):
            #value in dictionary?
            if(addr in self.dictionary):
                return self.dictionary[addr]

            #value not yet existing => remember it and search for it later again
            self.unknownIdentifiers.add(addr)
            return "postrun"
        else:
            #complex expression or own variables

            #constants like ONE, (ONES ommitted), ZERO
            if(match(r"ONE|One|one", addr)):
                return 1
            elif(match(r"ZERO|Zero|zero", addr)):
                return 0

            #"simple" Integer-Operations
            if(match(r"(Add|Substract|Multiply|Divide)\s*\(\s*.*,.*\s*\)", addr)):

                #extract function
                fct = findall(r"(\w*)\s*\(.*\)", addr)
                if(len(fct) != 1):
                    debug.error("more than one function in line: {0}, extracted functions: {1}".format(addr, fct))
                else:
                    fct = fct[0]

                #there are 2 parameters in each of these functions
                #this means there are four cases:
                # - Func( Func(...) , Func(...) )
                # - Func( Param, Func(...) )		param without brackets!
                # - Func( Func(...), Param)
                # - Func( Param, Param)
                #they are tested here after each other:
                tmp = findall(r"(Add|Substract|Multiply|Divide)\s*\(\s*([^\(]*\(.*\))\s*,\s*([^\(]*\(.*\))\s*\)", addr)
                if(not tmp):
                    tmp = findall(r"(Add|Substract|Multiply|Divide)\s*\(\s*([^\(,\)]*)\s*,\s*([^\(]*\(.*\))\s*\)", addr)
                    if(not tmp):
                        tmp = findall(r"(Add|Substract|Multiply|Divide)\s*\(\s*([^\(]*\(.*\))\s*,\s*([^\(,\)]*)\s*\)", addr)
                        if(not tmp):
                            tmp = findall(r"Add\s*\(\s*([^\(,\)]*)\s*,\s*([^\(,\)]*)\s*\)", addr)
                            if(not tmp):
                                debug.error("parsing error with expression: {0}".format(addr))

                #always searched for both parameters => list of 2 parameters => list should have size 1
                #e.g. [(param1, param2)] - wrong would be sth like: [(param1), (param2, param3)]
                if(len(tmp) != 1 or len(tmp[0]) != 2):
                    debug.error("parsing error with expression: {0}".format(addr))

                #parse the parameters (recursively)
                param1 = self.parse(tmp[0][0])
                param2 = self.parse(tmp[0][1])

                #check return values, both digits => calculate it
                if(str(param1).isdigit() and str(param2).isdigit()):
                    #eval the function
                    if(fct == "Add"):
                        return param1 + param2
                    elif(fct == "Substract"):
                        return param1 - param2
                    elif(fct == "Multiply"):
                        return param1 * param2
                    elif(fct == "Divide"):
                        return param1 / param2
                    else:
                        debug.error("Unknown function {0} even though it was filtered. This should never happen".format(fct))
                elif(param1 == "CRITICAL" or param2 == "CRITICAL"):
                    return "CRITICAL"
                elif(param1 == "suspicous" or param2 == "suspicous"):
                    return "suspicous"
                elif(param1 == "unknown" or param2 == "unknown"):
                    return "unknown"
                elif(param1 == "postrun" or param2 == "postrun"):
                    return "postrun"
                else:
                    debug.error("Can not parse function: Add with params: {0} and {1}".format(param1, param2))
            else:
                #unknown complex expressions or variables are fishy
                debug.warning("function-address '{0}' can not be evaluated".format(addr))
                return "suspicious"
            #endif
        #endif
    #end def
#end class

# ----- main class -----
class scanACPITables(common.AbstractWindowsCommand, linux_common.AbstractLinuxCommand):
    """Analyse dumped ACPI tables regarding rootkits."""

    # ----- constructor -----
    def __init__(self, config, *args, **kwargs):
        #setup
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

        # --- CONFIG ---
        #constants
        #regex
        self.FOLDERS = "0x[0-9a-f]*"
        self.FILES = "....(_\d+){0,1}" #scan all files with 4 chars in the middle (or 4 chars + underscore + number for SSDTs!)
        #suffixes, dont forget the "." in front!
        self.ASL = ".dsl"

        #parameters
        self._config.add_option('PATH', short_option = 'p', default = './dumpedTables',
                                help = 'Path to folder with dumped ACPI tables ' + 
                                '(= folder containing the 0x123abcde/ folders). ',
                                action = 'store', type = 'str')
        self._config.add_option('OUTPUTLENGTH', default = '70',
                                help = 'The length of the output for table colum "function"',
                                action = 'store', type = 'str')
        self._config.add_option('EXPERIMENTAL', short_option = 'x', default = False,
                                help = 'Scan for a wider range of potential suspicious functions. ' +
                                'This might result in much more false-positives!',
                                action = 'store_true')
        self._config.add_option('DUMP', default = False,
                                help = 'Call plugin dumpACPITables (with default values, i.e. including iasl) before scanning.',
                                action = 'store_true')
        # --------------

        #variables
        self.kernel_address_space = None
        self.physical_address_space = None
        self.parser = None
        self.reset()

    def reset(self):
        self.keyboard = list()
        if(self.parser != None):
            self.parser.reset()

    # ----- helpers -----

    #evaluate a line if there are critical or suspicious
    #functions in it, otherwise return "nofunc" (= uncritical)
    def checkLine(self, line, postrun = False):
        #potential critical: Load, LoadTable, Unload
        #(can be used to load new code which we can not scan here in dead analysis)
        mat = findall(r"Load\s*\(.*\).*|LoadTable\s*\(.*\).*|Unload\s*\(.*\).*", line)
        if(mat):
            return "suspicious"
        
        #if experimental scanning => scan for more potential suspicious functions
        if(self._config.EXPERIMENTAL):
            #keyboard interrupt IRQ1 is suspicious
            mat = findall(r".*IRQ1.*", line)
            if(mat):
                return "suspicious"

            #check for 2 or more keyboards PNP0300-PNP0344 (= suspicious)
            mat = findall(r"PNP03([0-3][0-9]|4[0-4])", line)
            if(mat):
                if(not postrun):
                    self.keyboard.append(line)
                    return "postrun"
                else:
                    if(len(self.keyboard) > 1):
                        return "suspicious"
                    else:
                        return "nofunc"
                    #end if
                #end if
            #end if
        #end if

        #get OperationRegion and check in which area it is operating
        mat = findall(r"OperationRegion\s*\(\s*\w*\s*,\s*([^,]*)\s*,.*\)", line)
        if(mat):
            if(len(mat) != 1):
                debug.error("Cannot parse OperationRegion: {0} - match: {1}".format(line, mat))
            else:
                mat = mat[0]

            #check crit-level
            if(match(r"(SystemMemory|0)", mat)):
                #check if call is critical
                return self.evalSystemMemoryCall(line)

            #suspicious values
            #CMOS 5, IPMI 7, GeneralPurposeIO 8
            elif(match(r"(CMOS|5|IPMI|7|GeneralPurposeIO|8)", mat)):
                return "suspicious"

            #values that seem ok:
            #SystemIO 1, PCI_Config 2, EmbeddedControl 3, SMBus 4, PCIBARTarget 6, GenericSerialbus 9
            elif(match(r"(SystemIO|1|PCI_Config|2|EmbeddedControl|3|SMBus|4|PCIBARTarget|6|GenericSerialbus|9)", mat)):
                return "seems ok"
            else:
                #unknown value
                debug.warning("Unknown value in OperationRegion: {mat}".format(mat))
                return "unknown"
        else:
            #findall above can be tricked by functions over 2 lines! e.g. closing bracket in second line
            if(findall(r".*OperationRegion.*", line)):
                debug.warning("Found OperationRegion but can not parse it!")
                debug.warning(line)
            return "nofunc"
        #end if

    #----------------------- end def -----------------------

    #function to evaluate a OperationRegion-call to memory
    #if the addr is in kernel space this is critical
    #otherwise this seems ok
    def evalSystemMemoryCall(self, line):
        #extract address and length (both can be complex expressions! => . instead of \w)
        address = findall(r"OperationRegion\s*\([^,]+,[^,]+,\s*(.*)\s*,[^,]+\).*", line)
        length = findall(r"OperationRegion\s*\([^,]+,[^,]+,.*,\s*([^,]+)\s*\).*", line)
        if(len(address) != 1 or len(length) != 1):
            debug.warning("Line {0} can not be parsed! (Multiple addresses or lengths)".format(line))
            return "unknown"
        else:
            address = address[0]
            length = length[0]

        #parse addresses
        address = self.parser.parse(address)
        #if not number, then it's already a return string
        if(not str(address).isdigit()):
            return address
        length = self.parser.parse(length)
        if(not str(length).isdigit()):
            return length

        #create end
        address_end = address + length

        #check all kernel-address-spaces
        for block in self.kernel_address_space.get_available_addresses():
            #init
            start = int(self.kernel_address_space.vtop(block[0]))
            end = start + int(block[1])

            #check if in interval
            #start in interval
            if(start < address and address < end):
                return "CRITICAL"
            #end in interval
            elif(start < address_end and address_end < end):
                return "CRITICAL"
            #whole interval in area
            elif(address <= start and end <= address_end):
                return "CRITICAL"
            elif(address_end < start):
                #kernel address spaces are bigger than end-address of given line
                #since kernel address space comes sorted => stop here
                break
            #end if
        #end for

        return "seems ok"

    #----------------------- end helpers -----------------------

    #validity check (optional)
    @staticmethod
    def is_valid_profile(profile):
        """Returns true if the plugin is valid for the current profile"""
        return (profile.metadata.get('os', 'unknown') == 'windows') or (profile.metadata.get('os', 'unknown') == 'linux')
    
    #----------------------- end def -----------------------

    #calculate function to do the whole work
    def calculate(self):
        #check if "path" exists
        if(not self._config.DUMP and not os.path.isdir(self._config.PATH)):
            debug.error("path {0} does not exist".format(self.PATH))
        #end if
        
        #load kernel space (= virtual address space) to check suspicious addresses against kernel
        self.kernel_address_space = utils.load_as(self._config)
        if(not self.is_valid_profile(self.kernel_address_space.profile)):
            debug.error("Unsupported profile: {0}".format(
                    self.kernel_address_space.profile.metadata.get('os', 'unknown')))

        #load physical address space
        self.physical_address_space = utils.load_as(self._config, astype = 'physical')
        if(not self.is_valid_profile(self.physical_address_space.profile)):
            debug.error("Unsupported profile: {0}".format(
                    self.physical_address_space.profile.metadata.get('os', 'unknown')))

        #call dumpACPITables if requested
        if(self._config.DUMP):
            debug.debug("Calling plugin dumpACPITables")
            #dump all ACPI tables (calculate is a generator! thus call until StopIteration)
            dumpACPImodule = dumpACPITables.dumpACPITables(self._config)
            gen = dumpACPImodule.calculate()
            while True:
                try:
                    gen.next()
                except StopIteration:
                    break
            #end while
        #end if
        
        #init
        self.parser = Parser(self.physical_address_space)

        #search PATH for ASL files
        for root, dirs, files in os.walk(self._config.PATH):
            for f in files:
                fullpath = os.path.join(root, f)

                #filter files
                if(match(escape(self._config.PATH) + "/" + self.FOLDERS +
                         "/" + self.FILES + escape(self.ASL), fullpath)):

                    #init
                    index = 0
                    statistic = dict()

                    #folder of file (0x....)
                    folder = findall(r"0x[0-9a-f]*", fullpath)[0]

                    #open file
                    fobj = open(fullpath, "r")

                    #scan for bad functions
                    for line in fobj:
                        #delete leading and following whitespaces
                        line = line.lstrip().rstrip()

                        #check if line includes some address definitions
                        identifier = self.parser.store_address(line)
                        if(identifier != False):
                            #Field-call
                            self.parser.parse_Field_call(line, fobj, identifier)
                            continue
                        #end if

                        #eliminate double operationregion lines (if line already in statistic, goto next one)
                        if(match(r"OperationRegion", line) and True in map(lambda x: line == x[1], statistic.values())):
                            continue

                        #evaluate line and save it
                        check = self.checkLine(line)
                        if(check != "nofunc"):
                            statistic.update({ index : [folder + "/" + f, line, check]})

                            #yield all lines that are not "postrun"
                            #these can (in not broken dsl files)
                            #later be evaluated
                            if(check != "postrun"): #TODO: only critical?
                                yield statistic[index]
                            #end if

                            #next
                            index += 1
                        #end if
                    #end for

                    #post-run to identify (until now) unknown symbols
                    for s in statistic.values():
                        if(s[2] == "postrun"):
                            s[2] = self.checkLine(s[1], True)
                            #reset all "postrun" with suspicious
                            #it's very strange if the symbols in that expression
                            #cannot be found in the whole file!
                            if(s[2] == "postrun"):
                                debug.warning("function call cannot be evaluated after scanning full file!")
                                s[2] = "suspicious"
                            #end if
                            #new value => yield it
                            if(s[2] != "nofunc"):
                                yield s
                            #end if
                        #end if
                    #end for

                    #close file
                    fobj.close()
                    self.reset()
                else:
                    continue
            #end for
        #end for

    #----------------------- end def -----------------------
    
    def render_text(self, outfd, data):
        #print header
        outfd.write("\ntable column \"Rootkit?\" may have values (seems ok/unknown/suspicious/CRITICAL)\n")

        self.table_header(outfd, [
        	#length of prefix (0x........ = 10) suffix, signature (=4) and additional 3 spaces
                ("File", str(10 + 4 + len(self.ASL) + 3)),
                ("Function", str(self._config.OUTPUTLENGTH)),
                ("Rootkit?", "11") #"suspicious" => max 10 chars + addit. 1
                ])

        #loop over data
        latest_file = None
        for (f, fct, check) in data:
            #format output
            if(latest_file == None):
                latest_file = f
            if(latest_file != f):
                outfd.write("\n")
                latest_file = f

            #print
            self.table_row(outfd, f, fct, check)
        #end for loop

    #----------------------- end def -----------------------

#EOF
