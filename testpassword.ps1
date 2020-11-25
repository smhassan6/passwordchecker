#requires -version 4

<#
.SYNOPSIS

Check password against leaked password database from https://haveibeenpwned.com/ using the Pwned Passwords V2 API https://api.pwnedpasswords.com/range/<hashPrefix>.

.DESCRIPTION

Only the first 5 characters of the password string hash is checked against the API (k-anonymity). The API returns a list of all passwords matching the hash prefix, then the script checks if the suffix is present or not.
More info on the HIBP API at https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/.

.PARAMETER Password
Enter the password to check.

.PARAMETER SecurePassword
Switch to enable secure prompt for password.

.EXAMPLE

.\Test-LeakedPasswordHIBP.ps1 -password "P@ssw0rd"

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
    [string]$Password,

    [Parameter(Mandatory=$False)]
    [switch]$SecurePassword
)

if ($SecurePassword) {

    $Credentials = Get-Credential -Message "Enter the password to test" -UserName "dummy"
    $Password = $credentials.GetNetworkCredential().Password

} else {
    
    if ($Password -eq "") {

        $Password = Read-Host -Prompt "Enter the password to test. The Password must meet complexity requirements"
	if (($Password -cmatch '[a-z]') -and ($Password -cmatch '[A-Z]') -and ($Password -match '\d') -and ($Password.length -match '^([7-9]|[1][0-9]|[2][0-5])$') -and ($Password -match '!|@|#|%|^|&|$|_')) 
	{
		Write-Output "$Password is a valid password. Meets complexity standards!"
	}
	else
	{
		Write-Output "$Password is not a valid password. Does not meet complexity standards!"
	}
}}

#Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#Create SHA-1 hash from string
Function Get-StringHash()
{

    [CmdletBinding()]
    Param (
          [Parameter(Mandatory=$True)]
          [String]$inputString
    )

    $Private:outputHash = [string]::Empty
    $hasher = New-Object -TypeName "System.Security.Cryptography.SHA1CryptoServiceProvider"
    $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString)) | ForEach-Object { $outputHash += $_.ToString("x2") }
    $outputHash.ToUpper()

}

$stringHash = Get-StringHash -inputString $Password
$hashPrefix = $stringHash.Substring(0, 5)
$hashSuffix = $stringHash.Substring(5, ($stringHash.Length - 5))

try {

    $response = Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$($hashPrefix)" -Method Get -ErrorVariable errorRequest

}
catch {

    Write-Output "Error with the request!"
    Write-Output $errorRequest
    break

}

if ($response -ne $null) {

    $findHashSuffix = $response.Contains($hashSuffix)

    if ($findHashSuffix -eq $true) {

        $result = $response.Substring($response.IndexOf($hashSuffix), $response.IndexOf([System.Environment]::NewLine, $response.IndexOf($hashSuffix)) - $response.IndexOf($hashSuffix))
        $resultCount = ($result.Split(":"))[1]

        Write-Output "Your password has been found $($resultCount) times!"
	$file= "$($ENV:USERProfile)\Desktop\password.txt"
	Get-ADReplAccount -All -Server 'WIN-EML611ONL36.lab6.com' -NamingContext "dc=lab6,dc=com" | Test-PasswordQuality -WeakPasswords $Password -IncludeDisabledAccounts -WeakPasswordsFile $file
    }
    else {

        Write-Output "Your password has not been found."

    }

}
else {

    Write-Output "No occurence of the hash prefix found."

}
