#extract features here that match mlmd server features
import sys, pefile, datetime, re, entropy, json, numpy

#to use this module, use the following example code
#import feature_extractor
#output = feature_extractor.get_features("LOCATION TO EXE FILE")

#output will be JSON format

#Function that lets up search for data in strings
def strsearch(string, data):
    if len(re.findall(string,data)) > 0:
        return 1
    return 0

def get_features(file):
    pe = pefile.PE(file)
    binary_data = open(file,"rb").read()

    entry_point_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    basecode = pe.OPTIONAL_HEADER.BaseOfCode
    number_of_symbols = pe.FILE_HEADER.NumberOfSymbols

    file_entropy = entropy.shannon_entropy(binary_data)

    compile_timestamp = pe.FILE_HEADER.TimeDateStamp
    compile_time = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    now = datetime.datetime.now()
    future = 0
    if compile_time > now:
        future = 1

    pe_dll_list = ""
    pe_dll = []
    pe_function_list = ""
    pe_func = []
    pe_section_list = ""

    #If imports are more than 0
    if len(pe.DIRECTORY_ENTRY_IMPORT) > 0:
        #for each import
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            #add dll name to list and append
            pe_dll_list += entry.dll.lower() + " "
            pe_dll.append(entry.dll.lower())
            #for each dll, if it imports more than 0 functions
            if len(entry.imports) > 0:
                #for each import, get name and add it to list and append
                for imp in entry.imports:
                    if imp.name:
                        pe_function_list += imp.name.lower() + " "
                        pe_func.append(imp.name.lower())
    #for each section in PE file, add name to the list
    for section in pe.sections:
        if section.Name:
            pe_section_list += section.Name.lower() + " "

    number_of_sections = len(pe.sections)
    number_of_dlls = len(set(pe_dll))
    number_of_funcs = len(set(pe_func))

    #Define our functions
    suspicious_functions = {}
    suspicious_functions['registry'] = ['RegCloseKey' 'RegOpenKey', 'RegQueryValue', 'RegSetValue', 'RtlCreateRegistryKey', 'RtlWriteRegistryValue']
    suspicious_functions['antianalysis'] = ['CheckRemoteDebuggerPresent','DebugActiveProcess','FindWindow','GetLastError','IsDebuggerPresent', 'sleep', 'OutputDebugString','GetAdaptersInfo','FindWindow','GetTickCount','NtQueryInformationProcess','NtSettInformationProcess','QueryPerformanceCounter']
    suspicious_functions['packing'] = ['VirtualAllocEx','LoadLibrary','VirtualFree','GetProcAddress','VirtualProtectEx','LdrLoadDll','LoadResource']
    suspicious_functions['exec'] = ['CommandLineToArg','ShellExecute','system','WinExec']
    suspicious_functions['keylog'] = ['SetWindowsHook','RegisterHotKey','GetKeyState','MapVirtualKey','CallNextHookEx','AttachThreadInput','GetKeyState','GetForegroundWindow','GetAsyncKeyState','SetWindowsHookEx']
    suspicious_functions['networking'] = ['listen','socket','accept','bind','connect','send','recv','FtpPutFile','InternetOpen','InternetOpenUrl','InternetReadFie','InternetWriteFile','ConnetNamedPipe','PeekNamedPike','gethostbyname','inet_addr']
    suspicious_functions['screenshot'] = ['BitBlt','GetDC']
    suspicious_functions['crypto'] = ['CryptDecrypt','CryptGenRandom','CryptAcqureContext']
    suspicious_functions['privesc'] = ['SetPrivilege','LookupPrivilege','AdjustTokenPrivilege','isNTAdmin','SamIConnect','SamIGetPrivateData','SamQueryInformationUse']
    suspicious_functions['manipulation'] = ['CreateRemoteThread','WriteProcessMemory','ReadProcessMemory','OpenProcess','NtOpenProcess','NtReadVirtualMemory','NtWriteVirtualMemory','MapViewofFile','Module32First','Module32Next','OpenMutex','OpenProcess','QueueUserAPC','ResumeThread','SetFileTime','SfcTerminateWeatherThread','SuspendThread','Thread32First','Thread32Next','WriteProcessMemory']
    suspicious_functions['service'] = ['CreateService','ControlService','OpenSCManager','StartServiceCtrlDispatcher']
    suspicious_functions['information'] = ['GetSystemDefaultLangId','IsWoW64Process','GetVersionEx','gethostname','EnumProcesses','EnumProcessModules','GetModuleFileName','GetProcAddress','LsaEnumerateLogonSessions','NetShareEnum','NetQueryDirectoryFile','Process32First','Process32Next','GetTempPath']
    suspicious_functions['create'] = ['CreateFile','CreateFileMapping','CreateMutex','CreateProcess']
    suspicious_functions['dll'] = ['DllCanUnloadNow','DllGetClassObject','DllInstall','DllRegisterServer','DllUnregisterServer']
    suspicious_functions['find'] = ['FindFirstFile','FindNextFile','FindResource','WSAStartup']
    suspicious_functions['persistent'] = ['NetScheduleJobAdd']

    #If rawsize is 0, it's typically a sign of packing
    rawsize = 0
    for section in pe.sections:
        if section.SizeOfRawData == 0:
            rawsize = 1

    #packer section names. When packed using one of the packers here, it will change section name to the packers name
    packer_section_names = ['upx','aspack','fsg','mpress']

    #DLL list
    dll_names = ['kernel32.dll','advapi32.dll','user32.dll','gdi32.dll','ws2_32.dll','ntdll.dll','crypt32.dll','shell32.dll','wsock32.dll','wininet.dll','msvcrt.dll']

    #DLL usage detection
    dll_names_detection = {}
    for dll in dll_names:
        if dll.lower() in pe_dll_list:
            dll_names_detection[dll] = 1
        else:
            dll_names_detection[dll] = 0

    #Packer usage detection
    packer_section_names_detection = {}
    for packer in packer_section_names:
        if packer in pe_section_list:
            packer_section_names_detection[packer] = 1
        else:
            packer_section_names_detection[packer] = 0

    #ADD function detection
    suspicious_functions_detection = {}
    for category in suspicious_functions:
        suspicious_functions_detection[category] = {}
        for function in suspicious_functions[category]:
            if strsearch(function.lower(),pe_function_list):
                suspicious_functions_detection[category][function] = 1
            else:
                suspicious_functions_detection[category][function] = 0

    return_data = {}
    return_data["entry_point_address"]=entry_point_address
    return_data["basecode"] = basecode
    return_data["number_of_symbols"] = number_of_symbols
    return_data["file_entropy"] = file_entropy
    return_data["compile_timestamp"] = compile_timestamp
    return_data["future"] = future
    return_data["number_of_sections"] = number_of_sections
    return_data["number_of_dlls"] = number_of_dlls
    return_data["number_of_funcs"] = number_of_funcs
    return_data["rawsize"] = rawsize
    for category in suspicious_functions_detection:
        for function in suspicious_functions_detection[category]:
            return_data[category+"_"+function] = suspicious_functions_detection[category][function]
    for dll_name in dll_names_detection:
        return_data[dll_name] = dll_names_detection[dll_name]
    for packer_name in packer_section_names_detection:
        return_data[packer_name] = packer_section_names_detection[packer_name]
    return json.loads(json.dumps(return_data))

