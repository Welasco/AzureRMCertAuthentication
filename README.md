# ExchangeBuild
Powershell Module to Setup a Certificate Based Authentication on AzureRM for Powershell

# How to Install

This Module is Published at https://www.powershellgallery.com/packages/AzureRMCertAuthentication/

In order to install just open the powershell as Administrator and type: 

Install-Module AzureRMCertAuthentication

Import-Module AzureRMCertAuthentication

# How to use this Module

  This Module Create or Remove a AzureRMCertAuthentication.

  Create AzureRMCertAuthentication to avoid password prompts.

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

   # Creating AzureRMCertAuthentication 
   New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription1
   This Example will create a AzureRMCertAuthentication and export a function named: Connect-AzureRMVMSubscription1

   # Creating AzureRMCertAuthentication 
   New-AzureRMCertAuthentication -FunctionName AzureRMVMSubscription2
   This Example will create a AzureRMCertAuthentication and export a function named: Connect-AzureRMVMSubscription2

   # Creating AzureRMCertAuthentication 
   Remove-AzureRMCertAuthentication -Function AzureRMVMSubscription1
   This Example will remove a AzureRMCertAuthentication named Connect-AzureRMVMSubscription2
