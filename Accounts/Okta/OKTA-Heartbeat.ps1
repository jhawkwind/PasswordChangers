﻿# Set initial status to fail until proven to succeed.
$exit_status = -1

# Transfer variables from call.
$DOMAIN = $Args[0]
$OKTA_API_KEY = $Args[1]
$USERNAME = $Args[2]
$PASSWORD = $Args[3]
$PORT = '443'

#Enter a key manually here if not specifying in the parameters.
#$OKTA_API_KEY = ''

# Check input validity.
if(-not ($OKTA_API_KEY -imatch '^[a-z0-9,._-]+$')) {
    throw [System.ArgumentException]::new("Invalid OKTA API Token provided.",'OKTA_API_KEY')
}

if(-not ($PORT -gt 0 -and $PORT -le 65535)) {
    throw [System.ArgumentOutOfRangeException]::new("Port number not in valid range between 1 and 65535 inclusive.",'PORT')
}

# Sanitize Username by encoding it, as this parameter is suseptible to injection otherwise.
try {
    $USERNAMEURL = [System.Web.HttpUtility]::UrlEncode("${USERNAME}")
}
catch [System.Management.Automation.RuntimeException] { # Handle this exception on servers that do not have the module loaded on PowerShell.
    try {
        # Reference: https://stackoverflow.com/questions/38408729/unable-to-find-type-system-web-httputility-in-powershell
        Add-Type -AssemblyName System.Web
        $USERNAMEURL = [System.Web.HttpUtility]::UrlEncode("${USERNAME}") # Now try again.
    }
    catch {
        Write-Error "FATAL: Cannot load URLEncoding library. Unhandled Exception Type of $($PSItem.Exception.GetType())"
        Write-Error $PSItem.ToString()
        $PSItem.Exception | Get-Member | Write-Debug
        throw $PSItem
    }
}
catch {
    Write-Error "Double FATAL: Unhandled Exception Type of $($PSItem.Exception.GetType())"
    Write-Error $PSItem.ToString()
    $PSItem.Exception | Get-Member | Write-Debug
    throw $PSItem
}

try {
    # Use DNS resolution to ensure a valid domain name was entered, fastest and easiest way to check.
    $DNSOutput = Resolve-DnsName -Name ${DOMAIN} -DnsOnly
    if(${DNSOutput}.Name.GetType().FullName -match "System.String") {
        $ResolvedName = ${DNSOutput}.Name
    }
    else {
        $ResolvedName = ${DNSOutput}.Name[0]
    }
}
catch {
    Write-Error "FATAL: Cannot resolve the domain name, please check the domain name parameter. $($PSItem.Execption.GetType())"
    $PSItem.Exception | Get-Member | Write-Debug
    throw $PSItem
}

# Set system configuration for secure communications.
# Uncomment below line to NOT Validate SSL Cert to trust store. (For Self Signed certs and testing only)
# [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }

# Require TLS 1.2. See: https://help.okta.com/en/prod/Content/Topics/Miscellaneous/okta-ends-browser-support-for-TLS-1.1.htm
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
}
catch {
    # In case administrator has disabled TLS 1.2 in SCHANNEL for some reason.
    throw [System.Net.ProtocolViolationException]::new("OKTA requires TLS 1.2 to be enabled. Unable to set SecurityProtocol to 'Tls12', please check SCHANNEL configuration.")
}

# Format hashtable to be converted to JSON.
$cred= @{
    username = "${USERNAME}"
    password = "${PASSWORD}"
    options = @{
        multiOptionalFactorEnroll = "false"
        warnBeforePasswordExpired = "false"
    }
}

$auth = $cred | ConvertTo-Json

# Compile the URL
$URL = "https://${ResolvedName}:${PORT}/api/v1/authn"

# Add the API key into the authentication header.
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization","SSWS ${OKTA_API_KEY}")

try {
    # -UserAgent 'ThycoticSecretServerPowerShell' -Body ${auth}
    $output = Invoke-RestMethod -Uri ${URL} -Method Post -Body ${auth} -ContentType 'application/json' -Headers ${headers}
}
catch [System.Net.WebException] {
    # Determine why login failed, make it a bit more user friendly and still provide detailed messages.
    # Reference: https://stackoverflow.com/questions/38419325/catching-full-exception-message
    if ( $PSItem.Exception.Response.StatusCode -match "BadRequest" ) {
        throw [System.Net.WebException]::new("Failure: Target account credentials are invalid or locked out.", $PSItem.Exception)
    }
    elseif ( $PSItem.Exception.Response.StatusCode -match "InternalServerError" ) {
        throw [System.Net.WebException]::new("Error: An Internal Server Error has occurred.", $PSItem.Exception)
    }
    elseif ( $PSItem.Exception.Response.StatusCode -match "Unauthorized" ) {
        throw [System.Net.WebException]::new("Failure: Target account or API credentials invalid.", $PSItem.Exception)
    }

    # Uncaught and unhandled and unknown exceptions get extra dump treatment.
    $PSitem.Exception.Response | Format-List * | Write-Debug
    Write-Error "Unable to retrieve session token: $($PSItem.ToString())"
    Write-Error "FATAL: Unknown API Exception Encountred $($PSItem.Exception.GetType())"
    $innerException = $PSItem.Exception.InnerExceptionMessage
    Write-Debug "Inner Exception: $innerException"
        $e = $_.Exception
        $msg = $e.Message
        while ($e.InnerException) {
          $e = $e.InnerException
          $msg += "`n" + $e.Message
        }
        Write-Error $msg
    $PSItem.Exception | Get-Member | Write-Debug
    
    throw $PSItem
}
catch {
    Write-Error "Double FATAL: Unhandled Exception Type of $($PSItem.Exception.GetType())"
    Write-Error $PSItem.ToString()
    $PSItem.Exception | Get-Member | Write-Debug
    throw $PSItem
}

$stateToken = ${output}.stateToken
$status = ${output}.status

if("${status}" -match "PASSWORD_EXPIRED" -Or "${status}" -match "PASSWORD_RESET" -Or "${status}" -match "PASSWORD_WARN") {
    $return_status = @{ "Status" = "Password Expired"; "stateToken" = "${stateToken}" }
    Write-Output ${return_status}
    $exit_status = 0
}
elseif("${status}" -match "SUCCESS") {
    $return_status = @{ "Status" = "Success"; "stateToken" = "${stateToken}" }
    Write-Output ${return_status}
    $exit_status = 0
}
elseif("${status}" -match "MFA_REQUIRED" -Or "${status}" -match "MFA_ENROLL") {
$return_status = @{ "Status" = "MFA Required"; "stateToken" = "${stateToken}" }
    Write-Output ${return_status}
    $exit_status = 0
}
else {
    Write-Output @{ "Status" = "Failure"; "SessionToken" = "" }
    # Any other status, count it as soft bad.
    # throw [System.ApplicationException]::new("Cannot parse authorization token.",$PSItem)
    $exit_status = 1;
}

exit $exit_status;