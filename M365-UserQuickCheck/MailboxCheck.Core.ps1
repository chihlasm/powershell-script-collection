# 5.1 because ExchangeOnlineManagement needs Windows PowerShell 5.1 (root CLAUDE.md, version floors).
#Requires -Version 5.1

<#
.SYNOPSIS
    SQ-007 STUB. Shared logic for Get-M365MailboxCheck.ps1: delegates, forwarding, inbox-rule
    signs, facts, verdict, HTML and ticket note. Every function fails with "not implemented"
    until the item is built; Tests\MailboxCheck.Tests.ps1 defines the interface.
#>

function Test-ExternalAddress { param([string]$Address, [string[]]$AcceptedDomain) throw 'Test-ExternalAddress: not implemented' }
function Get-MailboxDelegates { param([ValidateSet('FullAccess', 'SendAs', 'SendOnBehalf')][string]$Kind, [object[]]$Permission) throw 'Get-MailboxDelegates: not implemented' }
function Format-MailboxDelegateList { param([string[]]$Delegate) throw 'Format-MailboxDelegateList: not implemented' }
function Get-ForwardingSigns { param([object]$Mailbox, [string[]]$AcceptedDomain) throw 'Get-ForwardingSigns: not implemented' }
function Get-InboxRuleSigns { param([object[]]$Rule, [string[]]$AcceptedDomain) throw 'Get-InboxRuleSigns: not implemented' }
function Get-MailboxFactRows { param([object]$Mailbox, [object]$Statistics, [object]$ArchiveStatistics) throw 'Get-MailboxFactRows: not implemented' }
function Get-MailboxCheckAssessment { param([object[]]$Signs = @(), [object[]]$Gate = @()) throw 'Get-MailboxCheckAssessment: not implemented' }
function ConvertTo-MailboxCheckHtml { param([object]$Result) throw 'ConvertTo-MailboxCheckHtml: not implemented' }
function Get-MailboxCheckNote { param([object]$Result, [string[]]$EvidencePaths = @()) throw 'Get-MailboxCheckNote: not implemented' }
