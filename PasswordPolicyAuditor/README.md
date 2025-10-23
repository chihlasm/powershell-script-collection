# Password Policy Auditor

A comprehensive PowerShell script for auditing password policies across Active Directory Domain and Azure AD Tenant environments. This tool retrieves current password policy settings, provides detailed descriptions of each policy, and exports the information in multiple formats for compliance reporting and security assessments.

## Features

- **Dual Environment Support**: Retrieves password policies from both on-premises Active Directory and Azure AD
- **Detailed Descriptions**: Each policy setting includes clear explanations of its purpose and impact
- **Multiple Export Formats**: Supports CSV, HTML, and plain text output formats
- **Flexible Authentication**: Supports both interactive and credential-based Azure AD connections
- **Error Handling**: Graceful handling of missing modules and connection failures
- **Comprehensive Coverage**: Includes all major password policy settings for both environments

## Prerequisites

### For Active Directory Policies
- Windows domain-joined computer
- Active Directory PowerShell module (install RSAT tools)
- Domain user account with appropriate permissions

### For Azure AD Policies
- One of the following PowerShell modules:
  - MSOnline module (`Install-Module MSOnline`) - Recommended for password policies
  - AzureAD module (`Install-Module AzureAD`) - May not support password policy retrieval
- Azure AD administrative account or appropriate delegated permissions

## Installation

1. Clone or download the repository
2. Navigate to the PasswordPolicyAuditor folder
3. Ensure execution policy allows script running: `Set-ExecutionPolicy RemoteSigned`

## Usage

### Basic Usage

Run the script with default settings to audit both AD and Azure AD policies:

```powershell
.\Get-PasswordPolicies.ps1
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `OutputPath` | String | Current directory | Path where the output file will be saved |
| `OutputFormat` | String | CSV | Export format: CSV, HTML, or TXT |
| `IncludeAD` | Boolean | $true | Include Active Directory domain password policy |
| `IncludeAzureAD` | Boolean | $true | Include Azure AD tenant password policy |
| `AzureADCredential` | PSCredential | $null | Credentials for Azure AD authentication |

### Examples

#### Generate HTML Report
```powershell
.\Get-PasswordPolicies.ps1 -OutputFormat HTML -OutputPath "C:\Reports"
```

#### Audit Only Active Directory
```powershell
.\Get-PasswordPolicies.ps1 -IncludeAzureAD $false -OutputFormat TXT
```

#### Use Specific Credentials for Azure AD
```powershell
$cred = Get-Credential
.\Get-PasswordPolicies.ps1 -AzureADCredential $cred -OutputPath "C:\Audit"
```

#### Custom Output Location
```powershell
.\Get-PasswordPolicies.ps1 -OutputPath "\\Server\Share\Reports" -OutputFormat CSV
```

## Output Formats

### CSV Format
- Tabular data suitable for Excel or database import
- Includes columns: Policy Type, Setting, Value, Description
- Best for programmatic processing or spreadsheet analysis

### HTML Format
- Formatted web page with tables and styling
- Includes timestamp and report title
- Suitable for email distribution or web publishing

### Text Format (TXT)
- Plain text table format
- Compatible with all text editors
- Best for quick viewing or log files

## Policy Settings Retrieved

### Active Directory Domain Policies

| Setting | Description |
|---------|-------------|
| Minimum Password Length | Minimum number of characters required in a password |
| Password History Count | Number of previous passwords remembered to prevent reuse |
| Maximum Password Age | Maximum time a password can be used before requiring change |
| Minimum Password Age | Minimum time that must pass before a password can be changed |
| Password Complexity | Whether password must meet complexity requirements (uppercase, lowercase, numbers, symbols) |
| Lockout Threshold | Number of failed login attempts before account is locked |
| Lockout Duration | How long an account remains locked after lockout threshold is reached |
| Lockout Observation Window | Time window during which failed login attempts are counted toward lockout |

### Azure AD Tenant Policies

| Setting | Description |
|---------|-------------|
| Password Lifetime | Maximum time a password can be used before requiring change |
| Password History Count | Number of previous passwords remembered to prevent reuse |
| Minimum Password Length | Minimum number of characters required in a password |
| Password Complexity | Whether password must meet complexity requirements |

## Authentication Methods

### Active Directory
- Uses current user's domain credentials
- Requires domain membership and appropriate permissions
- No additional authentication needed

### Azure AD
- **Interactive**: Prompts for username/password when no credentials provided
- **Credential Object**: Accepts PSCredential object via `-AzureADCredential` parameter
- Supports both AzureAD and MSOnline modules automatically

## Error Handling

The script includes comprehensive error handling for common issues:

- **Missing Modules**: Clear messages when ActiveDirectory, AzureAD, or MSOnline modules are not installed
- **Connection Failures**: Graceful handling of network or authentication issues
- **Permission Issues**: Warnings when insufficient permissions prevent policy retrieval
- **Partial Success**: Continues with available data even if one environment fails

## Security Considerations

- Credentials are not stored or logged
- Uses secure authentication methods
- No data is transmitted externally
- Reports can be safely shared internally
- Consider file permissions on output locations

## Troubleshooting

### Common Issues

**"ActiveDirectory module not found"**
- Install RSAT (Remote Server Administration Tools) for your Windows version
- For Windows 10/11: Enable RSAT features in Optional Features

**"Neither AzureAD nor MSOnline module found"**
```powershell
# Install AzureAD module (recommended)
Install-Module AzureAD -Scope CurrentUser

# Or install MSOnline module (legacy)
Install-Module MSOnline -Scope CurrentUser
```

**"Access denied" errors**
- Ensure domain admin rights for AD policies
- Verify Azure AD admin role for cloud policies
- Check network connectivity

**Azure AD authentication issues in PowerShell ISE**
- PowerShell ISE may have compatibility issues with Azure AD interactive authentication
- Use regular PowerShell console instead: `powershell.exe -File .\Get-PasswordPolicies.ps1`
- Or use credential parameter: `$cred = Get-Credential; .\Get-PasswordPolicies.ps1 -AzureADCredential $cred`

**"HTTP request was forbidden with client authentication scheme 'Negotiate'"**
- This error indicates authentication issues with Azure AD
- Ensure your account has Azure AD administrative privileges
- Try using explicit credentials: `$cred = Get-Credential; .\Get-PasswordPolicies.ps1 -AzureADCredential $cred`
- Check if you're behind a proxy that blocks Azure AD authentication
- Verify your Azure AD tenant allows PowerShell connections

**Script won't run**
```powershell
# Check execution policy
Get-ExecutionPolicy

# Set execution policy if needed
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Output File Naming

Files are automatically named with timestamp:
- `PasswordPolicies_20231006_143052.csv`
- `PasswordPolicies_20231006_143052.html`
- `PasswordPolicies_20231006_143052.txt`

## Integration with Other Tools

The CSV output can be easily imported into:
- Microsoft Excel for analysis
- Power BI for dashboard creation
- SQL Server for historical tracking
- SIEM systems for compliance monitoring

## Version History

- **v1.0**: Initial release with AD and Azure AD support
- Comprehensive policy coverage
- Multiple export formats
- Error handling and authentication flexibility

## Contributing

To contribute improvements or report issues:
1. Test changes in a non-production environment
2. Ensure backward compatibility
3. Update documentation for new features
4. Test with different module versions

## License

This script is provided as-is for educational and administrative purposes. Ensure compliance with your organization's policies before use in production environments.
