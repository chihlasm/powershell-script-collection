# SMB Test.ps1 (SMB Diagnostic & Drive Mapping Script)

**Description**: A comprehensive PowerShell script for diagnosing SMB connectivity issues between Windows clients (7-11) and Windows Servers (2008-2022). The script performs step-by-step diagnostics including TCP connectivity testing, SMB session enumeration, protocol version detection, folder access testing, file listing, and network drive mapping.

**Configuration Parameters** (edit these in the script):
- `$ServerIP <string>`: Target SMB server IP address (e.g., "192.168.1.100")
- `$ShareName <string>`: Name of the SMB share to test (e.g., "SharedFolder")
- `$DriveLetter <string>`: Local drive letter for mapping (e.g., "Z")

**Usage Examples**:
- Run script with configuration: `.\SMB Test.ps1` (after editing the variables above)
- Test different shares: Modify $ShareName and $ServerIP in the script header
- Pre-deployment testing: Run before implementing SMB-dependent applications in production

**Diagnostic Steps Performed**:

1. **TCP Connectivity Test**: Verifies port 445 is accessible on the target server
2. **SMB Session Check**: Enumerates existing SMB connections to detect conflicts
3. **Protocol Detection**: Identifies SMB dialect (1, 2, or 3) in use
4. **Folder Access Test**: Validates read permissions on the target share
5. **File/Directory Listing**: Attempts to list contents of the share
6. **Drive Mapping**: Maps the share to a local drive letter for verification

**Features**:
- **Cross-Platform Compatibility**: Works from Windows 7 clients to Windows Server 2022
- **Automatic Fallback**: Uses net use for client OSes without Get-SmbConnection cmdlet
- **Color-Coded Output**: Green (Pass), Yellow (Warning), Red (Fail) for easy interpretation
- **SMB Protocol Detection**: Warns about SMB1 usage that can cause Explorer hangs
- **Network Drive Mapping**: Safely maps drives with error handling and cleanup
- **Detailed Logging**: Verbose output showing each step's results and troubleshooting info

**Requirements**:
- PowerShell 3.0+ on client systems
- Administrative privileges recommended for full diagnostics
- Network connectivity to target SMB server on port 445
- Read permissions on the target share (write needed only for drive mapping)

**Color-Coded Status Indicators**:
- <span style="color:green">Green</span>: Successful operations (PASS)
- <span style="color:yellow">Yellow</span>: Non-critical warnings (WARN)
- <span style="color:red">Red</span>: Failures requiring action (FAIL/ERROR)

**Common Issues Detected**:
- Firewall blocking SMB port 445
- SMB1 protocol negotiation problems (prevents Windows Explorer from opening shares)
- Authentication failures
- Permissions issues
- Network connectivity problems
- Server service not running

**Notes**:
- SMB1 detection triggers warnings as it's insecure and can cause UI hangs in modern Windows
- The script is read-only safe - no changes made to target servers or share configurations
- Drive mapping creates persistent connections unless manually removed
- Compatible with both local and remote SMB servers
- Can be used for troubleshooting before implementing Citric, RDS, or file server solutions
- Does not require installation of additional PowerShell modules
- Always test with read-only access first in production environments

**Troubleshooting Tips**:
- If TCP port 445 fails, check firewall rules and server network configuration
- SMB1 warnings indicate need to enable SMB2/3 on the target server
- Access failures typically indicate permission or authentication issues
- Mapping failures suggest share-level security or naming problems
