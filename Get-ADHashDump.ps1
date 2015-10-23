<#
  .SYNOPSIS
    Create password dump file for password cracking tools, e.g. for performing Active Directory password audits.
    - Password hashes of AD users are synced on-the-fly with a given Domain Controller - no need to export & extract NTDS.DIT + SYSTEM for password audits etc.
    - Must be excuted with 'Domain Admin' or 'Domain Controller' permissions (or equivalent).
    
    Requires PS Module "DSInternals" to be present on executing host. Please follow install instructions from there.
    - Found here: https://www.powershellgallery.com/packages/DSInternals/
    - More info:  https://www.dsinternals.com/en/

  .DESCRIPTION
    Create password dump file for password cracking tools, e.g. for performing Active Directory password audits.

  .PARAMETER strDomainController / DC / DomainController
    Input name of the Domain Controller to query, e.g. "DC1".

  .PARAMETER strNamingContext / NC / NamingContext
    Input the AD Naming Context, e.g. "DC=AD,DC=HEIDELBERG,DC=NU".

  .PARAMETER bolIncludeDisabledUsers / IncludeDisabledUsers / DisabledUsers / Disabled
    Also include disabled user accounts.

  .PARAMETER bolDumpOnlyHashesNT / OnlyHashesNT
    Create a dump file of NT hashes only.

  .PARAMETER bolDumpGenericNT / GenericNT
    Create a dump file of NT hashes in Generic format.

  .PARAMETER bolDumpPWDumpNT / PWDumpNT
    Create a dump file of NT hashes in PWDump format.

  .EXAMPLE
    PS C:\> Get-ADHashDump -DC 'DC1' -NC 'DC=AD,DC=HEIDELBERG,DC=NU' -PWDumpNT -Verbose

    1. Contact 'DC1' and as for enabled users under Naming Context 'DC=AD,DC=HEIDELBERG,DC=NU'.
    2. Create a dump file of NT hashes in PWDump format.
    3. Verbose logging to console.

  .EXAMPLE
    PS C:\> Get-ADHashDump -DC 'DC1' -NC 'dc=ad,dc=heidelberg,dc=nu' -PWDumpNT -GenericNT -OnlyHashesNT

    1. Contact 'DC1' and as for enabled users under Naming Context 'DC=AD,DC=HEIDELBERG,DC=NU'
    2. Create a dump file of NT hashes in PWDump format.
    3. Create a dump file of NT hashes in Generic format.
    4. Create a dump file of NT hashes only.

  .EXAMPLE
    PS C:\> Get-ADHashDump -DC 'DC1' -NC 'dc=ad,dc=heidelberg,dc=nu' -PWDumpNT -Disabled

    1. Contact 'DC1' and as for enabled - AND DISABLED - users under Naming Context 'DC=AD,DC=HEIDELBERG,DC=NU'
    2. Create a dump file of NT hashes in PWDump format.

  .LINK
    Get latest version here: https://github.com/ZilentJack/Get-ADHashDump

  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg
    Date created   : 23/10-2015
    Last modified  : 23/10-2015

    The very cool DSInternals module is authored by Michael Grafnetter - HUGE THANX to Michael for his great work and help! 

    Version history:
    - 1.00: Initial version (23/10-2015)

    Tested on:
     - WS 2012 R2 with WMF 5.0 Production Preview (both from member-server and from DC)

    Known Issues & possible solutions:
     KI-0001: - none at this point -

    Change Requests (not prioritized, may or may not be implemented in future version):
     CR-0001: Add option to include LM hashes if present.
     CR-0002: Add option to include password history if present.
     CR-0003: Add option for output (base) file name (default = 'hashes').

    Verbose output:
     Use -Verbose to output script progress/status information to console.
#>

Function Get-ADHashDump
{
  [CmdletBinding()]
  param
  (
    [Parameter(HelpMessage = 'Input name of the Domain Controller to query, e.g. "DC1".', Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [alias("DC","DomainController")]
    [string]
    $strDomainController,

    [Parameter(HelpMessage = 'Input the AD Naming Context, e.g. "DC=AD,DC=HEIDELBERG,DC=NU".', Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [alias("NC","NamingContext")]
    [string]
    $strNamingContext,

    [Parameter(HelpMessage = 'Only extract hashes from enabled user accounts (default).')]
    [alias("IncludeDisabledUsers", "DisabledUsers","Disabled")]
    [switch]
    $bolIncludeDisabledUsers = $False,

    [Parameter(HelpMessage = 'Create dump file with NT hashes only.')]
    [alias("OnlyHashesNT")]
    [Switch]
    $bolDumpOnlyHashesNT,

    [Parameter(HelpMessage = 'Create dump file with NT hashes only in generic format (username:hash).')]
    [alias("GenericNT")]
    [switch]
    $bolDumpGenericNT,

    [Parameter(HelpMessage = 'Create dump file with NT hashes onlu in PWDump format.')]
    [alias("PWDumpNT")]
    [switch]
    $bolDumpPWDumpNT
  )
  
    # ============ #
    # VARIABLES => #
    # ============ #
    $ScriptVersion = "1.0"
    $strOutputFileBaseName = 'hashes'

    Write-Verbose "Started - $ScriptVersion"

    Function GetRidFromSid
    {
        param
        ([string]$strSID)
        $strSID.Substring($strSID.LastIndexOf('-')+1)
    }

    Write-Verbose "Calling Get-ADReplAccount..."

    Try
    {
        If ($bolIncludeDisabledUsers)
        {
            $arrUserHashes = Get-ADReplAccount -All -Server $strDomainController -NamingContext $strNamingContext | Where {$_.SamAccountType -eq 'User'} | Select SamAccountName,@{Name="RID";Expression={GetRidFromSid $_.Sid}},@{Name="NTHashHex";Expression={ConvertTo-Hex $_.NTHash}}
        }
        Else # Also include disabled users
        {
            $arrUserHashes = Get-ADReplAccount -All -Server $strDomainController -NamingContext $strNamingContext | Where {$_.Enabled -eq $true -and $_.SamAccountType -eq 'User'} | Select SamAccountName,@{Name="RID";Expression={GetRidFromSid $_.Sid}},@{Name="NTHashHex";Expression={ConvertTo-Hex $_.NTHash}}
        }
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Verbose "FAIL: $ErrorMessage"
    }

    ForEach ($User in $arrUserHashes)
    {
        $strSamAccountName = $User.samAccountName
        $strRelativeID = $User.Rid
        $strNTHashHex = $User.NTHashHex
    
        If ($bolDumpOnlyHashesNT)
        {
            Write-Verbose "Dumping OnlyHashesNT > $strSamAccountName"
            $strFileName = $strOutputFileBaseName + "_OnlyHashesNT.txt"
            # Output: <hash> = Hashes only format
            # Avoid empty lines
            If ($strNTHashHex.Length -gt 0) {"$strNTHashHex" | Out-File $strFileName -Append}
        }

        If ($bolDumpGenericNT)
        {
            Write-Verbose "Dumping GenericNT > $strSamAccountName"
            $strFileName = $strOutputFileBaseName + "_GenericNT.txt"
            # Output: <username>:<hash> = Basic/Generic Format
            "$strSamAccountName`:$strNTHashHex" | Out-File $strFileName -Append
        }

        If ($bolDumpPWDumpNT)
        {
            Write-Verbose "Dumping PWDumpNT > $strSamAccountName"
            $strFileName = $strOutputFileBaseName + "_PWDumpNT.txt"
            # Output: <username>:<uid>:<LM-hash>:<NTLM-hash>:<comment>:<homedir>: = PWDump Format
            "$strSamAccountName`:$strRelativeID`:aad3b435b51404eeaad3b435b51404ee:$strNTHashHex`:`:`:" | Out-File $strFileName -Append
        }
    } # ForEach user loop

    Write-Verbose "Completed - $ScriptVersion"

} # Get-ADHashDump function end
