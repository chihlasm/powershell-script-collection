# Citrix VDA Diagnostics Tool

A PowerShell script to diagnose performance issues on Citrix Virtual Desktop Agent (VDA) servers, particularly those using FSlogix for user profile management.

## Features

- **Citrix Session Monitoring**: Detects active user sessions on the server
- **FSlogix Profile Analysis**: Identifies FSlogix VHD storage locations
- **Disk Performance Monitoring**: Measures disk queue length for storage drives
- **Storage Capacity Checks**: Monitors disk space usage and availability
- **CPU and RAM Analysis**: Tracks system resource usage with per-user calculations
- **Automated Recommendations**: Provides actionable insights for optimization

## Requirements

- Windows Server with PowerShell 5.1 or higher
- Citrix Virtual Apps/Desktop infrastructure (optional - script includes fallbacks)
- FSlogix (optional - script detects and adapts)
- Administrative privileges to access performance counters and registry

## Usage

### Basic Usage
```powershell
.\CitrixVDADiagnostics.ps1
```

### Remote Server Analysis
```powershell
.\CitrixVDADiagnostics.ps1 -ServerName "RemoteServer01"
```

### Verbose Output
```powershell
.\CitrixVDADiagnostics.ps1 -Verbose
```

## Parameters

- `ServerName`: Target server for diagnostics (default: local computer)
- `Verbose`: Show detailed session information

## Output

The script provides:

1. **Session Count**: Number of active Citrix sessions
2. **FSlogix Configuration**: Profile storage locations
3. **System Resources**: CPU and memory usage with per-user estimates
4. **Storage Analysis**: Disk queue length and space utilization
5. **Recommendations**: Actionable suggestions for performance issues

## Thresholds and Alerts

### Disk Queue Length
- **OK**: < 2.0
- **WARNING**: 2.0 - 5.0
- **CRITICAL**: > 5.0

### Storage Usage
- **OK**: < 80% used
- **WARNING**: 80% - 90% used
- **CRITICAL**: > 90% used

### CPU per User
- **WARNING**: > 80% per user
- **CRITICAL**: > 100% per user

### Memory per User
- **WARNING**: > 1GB per user
- **CRITICAL**: > 2GB per user

## Common Issues and Solutions

### High Disk Queue Length
- Upgrade to faster storage (SSD, NVMe)
- Distribute VHDs across multiple drives
- Implement storage tiering
- Check for storage controller bottlenecks

### Storage Space Issues
- Clean up old or unused profiles
- Implement profile archiving
- Add additional storage capacity
- Configure profile size limits

### High CPU/Memory Usage
- Add more CPU cores or RAM
- Optimize applications for VDI
- Implement session limits
- Use application virtualization

## FSlogix Integration

The script automatically detects FSlogix configuration and analyzes:
- Profile VHD locations from registry
- Storage performance for profile drives
- Space utilization for profile storage

## Citrix Integration

If Citrix PowerShell cmdlets are available, the script uses:
- `Get-BrokerSession` for accurate session information

Fallback methods are used when Citrix cmdlets are not available.

## Scheduling

For regular monitoring, create a scheduled task:

```powershell
# Create scheduled task to run daily at 9 AM
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Path\To\CitrixVDADiagnostics.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "CitrixVDAHealthCheck" -Description "Daily Citrix VDA diagnostics"
```

## Logging

Output can be redirected to a log file:
```powershell
.\CitrixVDADiagnostics.ps1 | Out-File -FilePath "C:\Logs\CitrixVDA_$(Get-Date -Format 'yyyyMMdd').log"
```

## Troubleshooting

### Script won't run
- Ensure PowerShell execution policy allows script execution
- Run as administrator
- Check PowerShell version compatibility

### Performance counters not available
- Verify user has access to performance monitor
- Check if performance counters are enabled
- Some counters may require specific Windows features

### Citrix cmdlets not found
- Install Citrix PowerShell SDK
- Use fallback session detection methods
- Script will continue with reduced functionality

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for diagnostic purposes. Use at your own risk.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review PowerShell error messages
3. Verify system requirements
4. Test on a non-production server first
