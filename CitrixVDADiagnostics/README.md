# Citrix VDA Diagnostics Tool

A comprehensive PowerShell script to diagnose performance issues on Citrix Virtual Desktop Agent (VDA) servers, particularly those using FSlogix for user profile management. The tool provides detailed analysis of system resources, storage performance, network I/O, and generates professional reports for documentation and sharing.

## Features

- **Citrix Session Monitoring**: Detects active user sessions using Citrix cmdlets or fallback methods
- **FSlogix Integration**: Automatically detects FSlogix version and analyzes profile VHD storage locations
- **Windows Update Monitoring**: Checks for pending Windows updates and critical security patches
- **Disk Performance Analysis**: Measures disk queue length for storage drives hosting user profiles
- **Storage Capacity Monitoring**: Tracks disk space usage with configurable thresholds
- **I/O Performance Diagnostics**: Measures read/write performance and latency for both local and network storage
- **System Resource Analysis**: Monitors CPU and RAM usage with per-user calculations
- **Automated Recommendations**: Provides actionable insights for performance optimization
- **Report Generation**: Exports results in HTML, CSV, JSON, or TXT formats
- **Color-coded Alerts**: Visual indicators for OK/WARNING/CRITICAL status levels

## Requirements

- Windows Server 2016+ with PowerShell 5.1 or higher
- Citrix Virtual Apps/Desktop infrastructure (optional - script includes fallbacks)
- FSlogix (optional - script detects and adapts)
- Administrative privileges to access performance counters and registry
- Windows Update service access for update checking

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

### Report Generation
```powershell
# Generate HTML report (default)
.\CitrixVDADiagnostics.ps1 -ExportReport

# Generate CSV report
.\CitrixVDADiagnostics.ps1 -ExportReport -ReportFormat CSV

# Generate JSON report
.\CitrixVDADiagnostics.ps1 -ExportReport -ReportFormat JSON

# Custom report path
.\CitrixVDADiagnostics.ps1 -ExportReport -ReportFormat HTML -ReportPath "C:\Reports\VDA_Report.html"
```

### Combined Usage
```powershell
# Remote server with verbose output and HTML report
.\CitrixVDADiagnostics.ps1 -ServerName "CitrixProd01" -Verbose -ExportReport -ReportFormat HTML
```

## Parameters

- `ServerName <string>`: Target server for diagnostics (default: local computer)
- `Verbose <switch>`: Show detailed session information and critical update counts
- `ExportReport <switch>`: Enable report generation
- `ReportFormat <string>`: Report format - HTML, CSV, JSON, or TXT (default: HTML)
- `ReportPath <string>`: Custom file path for report (auto-generates if not specified)

## Output

The script provides comprehensive diagnostics including:

1. **Session Information**: Active Citrix sessions with user details
2. **FSlogix Version**: Detected FSlogix version and installation status
3. **FSlogix Configuration**: Profile storage locations and VHD paths
4. **System Resources**: Real-time CPU and memory usage with per-user calculations
5. **Storage Analysis**: Disk usage, queue lengths, and capacity planning
6. **I/O Performance**: Read/write speeds and latency for local and network storage
7. **Windows Updates**: Count of pending updates with critical update alerts
8. **Recommendations**: Prioritized action items for performance optimization

### Report Formats

#### HTML Reports
- Professional, visually appealing with color-coded status indicators
- Executive summary dashboard with key metrics
- Detailed tables with comprehensive data
- Responsive design for various screen sizes
- Perfect for sharing with management and documentation

#### CSV Reports
- Data analysis friendly format
- Compatible with Excel and other spreadsheet applications
- Suitable for trending analysis and historical data
- Easy to import into databases or reporting tools

#### JSON Reports
- Structured data format for programmatic processing
- API integration friendly
- Suitable for automated monitoring systems
- Preserves all diagnostic data in structured format

#### TXT Reports
- Plain text format for simple documentation
- Easy to read and archive
- Suitable for logging and basic record keeping

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

### I/O Performance (Local Storage)
- **Read Performance**: < 50 MB/s (Red), 50-100 MB/s (Yellow), > 100 MB/s (Green)
- **Write Performance**: < 50 MB/s (Red), 50-100 MB/s (Yellow), > 100 MB/s (Green)
- **Total I/O**: < 100 MB/s (Red), 100-200 MB/s (Yellow), > 200 MB/s (Green)
- **Read Latency**: > 20ms (Red), 10-20ms (Yellow), < 10ms (Green)
- **Write Latency**: > 20ms (Red), 10-20ms (Yellow), < 10ms (Green)

### I/O Performance (Network Storage)
- **Read Performance**: < 25 MB/s (Red), 25-50 MB/s (Yellow), > 50 MB/s (Green)
- **Write Performance**: < 20 MB/s (Red), 20-40 MB/s (Yellow), > 40 MB/s (Green)
- **Total I/O**: < 50 MB/s (Red), 50-100 MB/s (Yellow), > 100 MB/s (Green)
- **Network Latency**: > 50ms (Red), 20-50ms (Yellow), < 20ms (Green)

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

## Network Storage Performance Guidelines

### Optimal Network Storage Speeds for FSlogix

For optimal Citrix VDA performance with FSlogix profiles, network storage should meet these minimum requirements:

#### **1GB Ethernet Networks**
- **Minimum Read Speed**: 25 MB/s sustained
- **Minimum Write Speed**: 20 MB/s sustained
- **Target Read Speed**: 50+ MB/s
- **Target Write Speed**: 40+ MB/s
- **Maximum Latency**: 20ms round-trip
- **Suitable for**: Up to 25 concurrent users per storage server

#### **10GB Ethernet Networks**
- **Minimum Read Speed**: 100 MB/s sustained
- **Minimum Write Speed**: 80 MB/s sustained
- **Target Read Speed**: 200+ MB/s
- **Target Write Speed**: 150+ MB/s
- **Maximum Latency**: 5ms round-trip
- **Suitable for**: Up to 100+ concurrent users per storage server

#### **Storage Protocol Recommendations**
- **SMB 3.0+**: Preferred for Windows environments
- **NFS**: Good alternative for mixed environments
- **iSCSI**: For block-level storage access
- **Fibre Channel**: For high-performance requirements

### Performance Impact Factors

#### **Network Infrastructure**
- **Switch Quality**: Enterprise-grade switches with adequate port density
- **Cable Quality**: Cat6/Cat6a for 1GbE, OM3/OM4 fiber for 10GbE
- **Network Congestion**: Isolate storage traffic on dedicated VLANs
- **Jumbo Frames**: Enable for improved large file transfer efficiency

#### **Storage Array Configuration**
- **RAID Configuration**: RAID 10 for best performance, RAID 5/6 for capacity
- **Cache Settings**: Optimize read/write cache ratios for VDI workloads
- **QoS Policies**: Implement quality of service for storage traffic
- **Multipathing**: Enable MPIO for redundancy and load balancing

#### **FSlogix-Specific Optimizations**
- **Profile Container Size**: Keep under 30GB per user for better performance
- **Concurrent Access**: Limit concurrent users per storage volume
- **Anti-Virus Exclusions**: Exclude FSlogix directories from real-time scanning
- **Compression**: Enable storage compression if supported

### Monitoring Recommendations

#### **Key Metrics to Monitor**
- **IOPS**: Input/Output Operations Per Second
- **Throughput**: MB/s read and write performance
- **Latency**: Response time for storage operations
- **Queue Depth**: Number of pending I/O operations
- **CPU Utilization**: Storage processor usage
- **Memory Usage**: Cache hit ratios and memory pressure

#### **Alert Thresholds**
- **Warning**: Performance drops below 80% of baseline
- **Critical**: Performance drops below 50% of baseline
- **Trend Analysis**: Monitor for gradual performance degradation

### Troubleshooting Network Storage Issues

#### **Common Performance Problems**
1. **High Latency**: Check network infrastructure and switch configurations
2. **Low Throughput**: Verify network speed/duplex settings and cable quality
3. **Intermittent Connectivity**: Check for network congestion or faulty hardware
4. **Storage Array Bottlenecks**: Monitor array CPU, memory, and cache usage

#### **Diagnostic Steps**
1. **Network Testing**: Use tools like `ping`, `tracert`, and `pathping`
2. **Performance Monitoring**: Run this diagnostic script during peak usage
3. **Storage Logs**: Review storage array logs for errors or warnings
4. **Configuration Review**: Verify network and storage settings match best practices

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
