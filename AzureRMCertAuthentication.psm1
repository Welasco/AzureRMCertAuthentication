<# 
 .Synopsis
  This Module Create or Remove a AzureRMCertAuthentication.
  Create AzureRMCertAuthentication to avoid password prompts.

 .Description
  This Modulo will Create an AzureRmADApplication and associate a Self-Signed Certificate.
  The main idea is to avoid multiple prompts for authentication each time you open Powershell.
  An additional function will be exported to the current user profile to be used to connect to AzureRM without password prompt.

  Example of a Function that will be exported:

    ##################### Function Connect-AzureRM #####################
    Function Connect-AzureRM{ 
        $TenantID = "' + $SessionContext.Tenant.Id + '"
        $thumb = "' + $SelfSignedCertificate.thumb + '" 
        $ApplicationID = [GUID]"' + $azureAdApplication.ApplicationId.Guid + '" 
        Add-AzureRmAccount -TenantId $TenantID -ServicePrincipal -CertificateThumbprint $thumb -ApplicationId $ApplicationID
        if($host.ui.RawUI.WindowTitle -eq "Windows PowerShell"){
            $host.ui.RawUI.WindowTitle = "Connected to: AzureRM"
        }
        elseif($host.ui.RawUI.WindowTitle.contains("Connected")){
            $host.ui.RawUI.WindowTitle = ($host.ui.RawUI.WindowTitle + " & AzureRM")
        }
    }
    ####################################################################
  
  One the AzureRMCertAuthentication is created you just type Connect-AzureRM to connect to AzureRM without password.

 .Example
   # Creating AzureRMCertAuthentication 
   New-AzureRMCertAuthentication
 .Example
   # Creating AzureRMCertAuthentication 
   Remove-AzureRMCertAuthentication

# A URL to the main website for this project.
ProjectUri = 'https://github.com/welasco/AzureRMCertAuthentication'
#>


Function CheckAzureSession{
    $Check = (Get-AzureRmContext).Account
    If($Check){
        return $true
    }
    else {
        return $false
    }
}

Function CreateSelfSignedCertificate {
    $currentDate = Get-Date
    $endDate = $currentDate.AddYears(1)
    $notAfter = $endDate.AddYears(1)
    $pwdStr = ([guid]::NewGuid()).guid.tostring().replace("-","")
    $dnsName = ($env:COMPUTERNAME + "-" + (Get-AzureRmContext).Subscription.Name.Replace(" ","") + ".AzurePowershell.local")
    $certPath = Split-Path $profile.CurrentUserAllHosts
    $dstPath = Join-Path -Path $certPath -ChildPath ($dnsName + ".pfx")
    $thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\localmachine\my -DnsName $dnsName -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
    $pwd = ConvertTo-SecureString -String $pwdStr -Force -AsPlainText
    Export-PfxCertificate -cert "cert:\localmachine\my\$thumb" -FilePath $dstPath -Password $pwd
    $return = New-Object PsObject @{
        currentDate=$currentDate
        endDate=$endDate
        pwd=$pwd
        dstPath=$dstPath
        thumb=$thumb
        dnsName=$dnsName
        certPath=$certPath
    }
    return $return
}

Function CreateKeyCredential{
    Param(
        [Parameter(Mandatory=$true)]
        [PsObject]$SelfSignedCertificate
    )
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($SelfSignedCertificate.dstPath, $SelfSignedCertificate.pwd)
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
    $keyId = [guid]::NewGuid()
    Import-Module AzureRM.Resources
    $keyCredential = New-Object  Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential
    $keyCredential.StartDate = $SelfSignedCertificate.currentDate
    $keyCredential.EndDate= $SelfSignedCertificate.endDate
    $keyCredential.KeyId = $keyId
    #$keyCredential.Type = "AsymmetricX509Cert"
    #$keyCredential.Usage = "Verify"
    $keyCredential.CertValue = $keyValue

    return $keyCredential
}


Function New-AzureRMCertAuthentication{
    $isSession = CheckAzureSession

    if ($isSession -eq $false) {
        Add-AzureRmAccount
    }

    $SelfSignedCertificate = CreateSelfSignedCertificate
    $PSADKeyCredential = CreateKeyCredential -SelfSignedCertificate $SelfSignedCertificate

    # Create the Azure Active Directory Application
    $azureAdApplication = New-AzureRmADApplication -DisplayName ($env:COMPUTERNAME + "-AzurePowershell-CertAuth") -HomePage ("https://" + $SelfSignedCertificate.dnsName) -IdentifierUris ("https://" + $SelfSignedCertificate.dnsName) -KeyCredentials $PSADKeyCredential

    # Create the Service Principal and connect it to the Application
    New-AzureRmADServicePrincipal -ApplicationId $azureAdApplication.ApplicationId

    Start-Sleep -Seconds 20

    # Give the Service Principal Reader access to the current subscription
    New-AzureRmRoleAssignment -RoleDefinitionName Owner -ServicePrincipalName $azureAdApplication.ApplicationId

    $SessionContext = Get-AzureRmContext

    $ExportFunction = '##################### Function Connect-AzureRM #####################
    Function Connect-AzureRM{ 
        $TenantID = "' + $SessionContext.Tenant.Id + '"
        $thumb = "' + $SelfSignedCertificate.thumb + '" 
        $ApplicationID = [GUID]"' + $azureAdApplication.ApplicationId.Guid + '" 
        Add-AzureRmAccount -TenantId $TenantID -ServicePrincipal -CertificateThumbprint $thumb -ApplicationId $ApplicationID
        if($host.ui.RawUI.WindowTitle -eq "Windows PowerShell"){
            $host.ui.RawUI.WindowTitle = "Connected to: AzureRM"
        }
        elseif($host.ui.RawUI.WindowTitle.contains("Connected")){
            $host.ui.RawUI.WindowTitle = ($host.ui.RawUI.WindowTitle + " & AzureRM")
        }
    }
    ####################################################################'

    $ExportFunction | Out-File -FilePath $profile.CurrentUserAllHosts -Append

    Write-Output "Now close your Powershell session and run Connect-AzureRM to connect!"
}

Function Remove-AzureRMCertAuthentication{
    try{
        $AzureRMADApp = Get-AzureRmADApplication -DisplayNameStartWith ($env:COMPUTERNAME + "-AzurePowershell-CertAuth")
        Remove-AzureRmADApplication -ObjectId $AzureRMADApp.ObjectId
        Write-Output "Now you safely remove the function on your Powershell Profile."
        Write-Output "Type: notepad $profile.CurrentUserAllHosts"
    }
    catch{
        Write-Output "To remove the a AzureRMCertAuthentication you must login again. Please type Login-AzureRmAccount"
    }
}

export-modulemember -function New-AzureRMCertAuthentication, Remove-AzureRMCertAuthentication

