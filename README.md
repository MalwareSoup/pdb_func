# pdb_func
Experimenting with minimal parsing of PDB files for function names and offsets

### Usage example - resolving offsets in the CallTrace field from Sysmon Event ID 10
In this simple example, I have the necessary PDB files for each DLL/EXE in the calltrace field downloaded from Microsoft's symbol server stored in a single folder
    import pdb_func
    from pathlib import Path, PureWindowsPath

    pdb_folder = "/path/to/folder/with/PDBs"

    # CallTrace pulled from Sysmon event ID 10
    trace = "C:\\Windows\\SYSTEM32\\ntdll.dll+5151a|C:\\Windows\\system32\\KERNELBASE.dll+131e7|C:\\Windows\\system32\\SHELL32.dll+a209b|C:\\Windows\\system32\\SHELL32.dll+2479db|C:\\Windows\\Explorer.EXE+6e4de|C:\\Windows\\Explorer.EXE+9adc|C:\\Windows\\Explorer.EXE+2fe0|C:\\Windows\\system32\\SHELL32.dll+9f0eb|C:\\Windows\\system32\\SHELL32.dll+a2c8a|C:\\Windows\\system32\\SHELL32.dll+a2de2|C:\\Windows\\system32\\SHLWAPI.dll+13843|C:\\Windows\\SYSTEM32\\ntdll.dll+215db|C:\\Windows\\SYSTEM32\\ntdll.dll+20c56|C:\\Windows\\system32\\kernel32.dll+1652d|C:\\Windows\\SYSTEM32\\ntdll.dll+2c541"

    calls = trace.split('|')

    # Since parsing PDBs is kinda slow, only parse each one once and save it in a dict
    print("[*] Parsing PDBs")
    pdbs = {}
    for call in calls:
      lib, offset = call.split("+")
      offset = int(offset,16)
      pdb_fn = lib.split("\\")[-1].split('.')[-2]
      pdb_file_path = Path("{}/{}.pdb".format(pdb_folder,pdb_fn.lower()))
      if pdb_fn not in pdbs.keys():
        pdb = pdb_func.PDB(pdb_file_path)
        pdb.parse_dbi()
        pdbs[pdb_fn] = pdb

    print("-"*50)
    for call in calls:
      lib, offset = call.split("+")
      offset = int(offset,16)
      pdb_fn = lib.split("\\")[-1].split('.')[-2]
      pdb = pdbs[pdb_fn]

      # Educated guess at the offset of the containing function - 
      # closest referenced function name with a lower offset than the one referenced in the call trace
      if len(pdb.omap_to_src.keys()) > 0:
        symbol_offset = max([i for i in list(pdb.omap_to_src.keys()) if offset > i and pdb.omap_to_src[i] in pdb.functions_by_offset.keys()])
        func_name = pdb.functions_by_offset[pdb.omap_to_src[symbol_offset]]
      else:
        symbol_offset = max([i for i in list(pdb.functions_by_offset.keys()) if offset > i])
        func_name = pdb.functions_by_offset[symbol_offset]

      print("{}.{} ({})".format(pdb_fn,func_name, hex(offset)))

#### Output

    [*] Parsing PDBs
    --------------------------------------------------
    ntdll.ZwOpenProcess (0x5151a)
    KERNELBASE.OpenProcess (0x131e7)
    SHELL32.?_GetShortcutPathOrAppIDFromPid@CStartMenuCacheAndAppResolver@@AEAAJKPEAGIPEAH1@Z (0xa209b)
    SHELL32.?GetShortcutForProcess@CStartMenuCacheAndAppResolver@@UEAAJKPEAPEAUIShellItem@@@Z (0x2479db)
    Explorer.__chkstk (0x6e4de)
    Explorer.?InternalResumeRT@CResolveWindowTask@CTaskBand@@UEAAJXZ (0x9adc)
    Explorer.?Run@CRunnableTask@@UEAAJXZ (0x2fe0)
    SHELL32.?TT_Run@CShellTask@@QEAAXPEA_N@Z (0x9f0eb)
    SHELL32.?ThreadProc@CShellTaskThread@@AEAAXXZ (0xa2c8a)
    SHELL32.?s_ThreadProc@CShellTaskThread@@SAKPEAX@Z (0xa2de2)
    SHLWAPI.ExecuteWorkItemThreadProc (0x13843)
    ntdll.RtlpTpWorkCallback (0x215db)
    ntdll.RtlRealSuccessor (0x20c56)
    kernel32.BaseThreadInitThunk (0x1652d)
    ntdll.RtlUserThreadStart (0x2c541)
