<# 
.SYNOPSIS

Invoke-EncryptionSimulator is designed to be a simple and safe way to emulate the encryption stage of a 
ransomware deployment to aid in development and testing of controls focusing on file system level 
changes rather than process related telemetry.

Author: Rob Willis (@b1t_r0t - robwillis.info)

.DESCRIPTION

Invoke-EncryptionSimulator is designed to be a simple and safe way to emulate the encryption stage of a 
ransomware deployment to aid in development and testing of controls focusing on file system level 
changes rather than process related telemetry. No additional scripts or modules are needed, everything 
needed to test is contained within this single script. Invoke-EncryptionSimulator was purposely built to 
be as lean and clean as possible with the intent to look more like an administrative tool rather than 
malware to hopefully avoid interference from security controls.

Invoke-EncryptionSimulator has the following capabilities:
Recursively encrypt or decrypt the contents of a specified folder (AES)
Optionally delete the original file(s) after encryption
Optionally restore decrypted files to the original names
Optionally cleanup old encrypted/decrypted files
Built-in logging

Invoke-EncryptionSimulator does not contain any sort of self propagation code, it is designed to be executed
in a stand alone fashion.

The following parameters are supported:
-TargetDir (-td) - The directory containing the files to be encrypted/decrypted
-Action (-a) - "Encrypt", "Decrypt", "Restore", or "Cleanup", default = Encrypt
-AesKey (-k) - The AES-256 key to be used to encrypt the files, 32 bytes converted to b64, default = dynamically generated at runtime
-AesIv (-i) - The initialization vector (IV) to be used for the AES encryption, 16 bytes converted to b64, default = dynamically generated at runtime
-DeleteOriginal - Destructive mode, will delete all of the original files after encryption
-DisableLog - Disable the log file
-LogLimit - Remove any old logs, keeping only the X most recent, default = 0/No limit
-Unattended - Skip the interactive safety prompt prior to execution

The script will execute in the following order:
- Check to see if logging is enabled
  - Clean up old logs if LogLimit is defined
  - Start logging or set to disabled 
- If decrypting, force DeleteOriginal to False
- Check the mandatory requirements for the script to run successfully
  - Target Directory, if the parameter is not specified via cli, the script will prompt
  - Verify the target directory exists
    - If it does not, exit
- Gather all of the relavent info related to the script for review before execution
- Verify prompt
  - If running with -Unattended parameter, skip check
  - If yes, pause 10 seconds as a last chance
  - If no, exit
- Begin looping through the targetDir
  - If the filename contains "encrypt" and not "decrypt" and the action is encrypt - Take no action
  - If the filename contains "encrypt" and not "decrypt and the action is decrypt - Decrypt the file
  - If the filename does not contain "encrypt" and does not contain "decrypt" and the action is encrypt - Encrypt the file
    - If the DeleteOriginal switch was specified, delete the original file
  - If the action is restore, remove the ".encrypted.decrypted" extension, restoring all files to the original name
  - If the action is cleanup, delete all the files ending with either .encrypted or .decrypted extensions
- Wrap up, stop logging

.EXAMPLE

Stage 1 - Encryption

Method 1 - Non-Destructive - Creates a copy of each file with a .Encrypted extension:
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Encrypt

Method 2 - Destructive - Creates a copy of each file with a .Encrypted extension and deletes the original file:
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Encrypt -DeleteOriginal

Note: If no key/iv is specified, a pair will be dynamically generated at run time and output to the console and log file


Stage 2 - Decryption

Non-Destructive - Creates a decrypted copy of all files with the .Encrypted extension:
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Decrypt -AesKey "Y1NxMHJ0bk13dTJUM2dhQQ==" -AesIv "cTFmYkNlNVE3WG85SERsTw=="


Stage 3 - Restore

Destructive - Restore all the decrypted files to their original filename/extension (removing the .decrypted),:
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Restore

Stage 4 - Cleanup

Delete all left over .Encrypted and/or .Decrypted files:
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Cleanup

#>

# Functions

# Custom pause
Function Pause {
	Write-Host -NoNewLine "| Press any key to continue...`n"
	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Time stamp
function time {
    $global:time = Get-Date -format "MMM-dd-yyyy_HH-mm"
}

# Count files and folders in directory - set the variables global so we can recalculate and use them outside of the function
function targetDirStats {
    $global:fileStatsCount = (Get-ChildItem $targetDir -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).count
    $global:dirStatsCount = (Get-ChildItem $targetDir -Directory -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).count
}

function b64-encode($string) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($string)
    $b64String =[Convert]::ToBase64String($bytes)
    $b64String
}

function RestoreFiles {
    Get-ChildItem -Path $targetDir -File -Recurse | ForEach-Object {
        if ($_ -match "`.encrypted`.decrypted" -And $action -match "restore") {
            Try {
                    $restoreName = $_ -replace ".encrypted.decrypted",""
                    $restoreFullPath = $_.FullName -replace ".encrypted.decrypted",""
                    "| $action - $_ `> " + $restoreName
                    Move-Item -Path $_.FullName -Destination $restoreFullPath -Force
                    "|"
                } Catch {
                    "| Something went wrong!"
                    "| Error message: $_"
                    "|"
                }
        }
    }
}

function DeleteFilesByExtension($extensions) {
    foreach ($Extension in $Extensions) {
        $FilesToDelete = Get-ChildItem -Path $targetDir -Filter "*$Extension" -Recurse
        
        foreach ($File in $FilesToDelete) {
            Write-Host "| Deleting - $File"
            Remove-Item -Path $File.FullName -Force
            "|"
        }
    }
}

function Encrypt-Decrypt-File($InputFilePath,$OutputFilePath,$Key,$IV,$Action) {

    # Create AES crypto service provider
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = [Convert]::FromBase64String($Key)
    $aes.IV = [Convert]::FromBase64String($IV)

    # Create file streams for input and output
    $inputFileStream = New-Object System.IO.FileStream($InputFilePath, [System.IO.FileMode]::Open)
    $outputFileStream = New-Object System.IO.FileStream($OutputFilePath, [System.IO.FileMode]::Create)

    if ($Action -eq "Encrypt") {
        # Create AES encryptor
        $encryptor = $aes.CreateEncryptor()

        # Create crypto stream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputFileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    }
    elseif ($Action -eq "Decrypt") {
        # Create AES decryptor
        $decryptor = $aes.CreateDecryptor()

        # Create crypto stream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputFileStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    }

    # Buffer for reading/writing data
    $buffer = New-Object byte[] 4096

    # Process the file
    while ($inputFileStream.Position -lt $inputFileStream.Length) {
        $bytesRead = $inputFileStream.Read($buffer, 0, $buffer.Length)
        $cryptoStream.Write($buffer, 0, $bytesRead)
    }

    # Close streams
    $cryptoStream.Close()
    $outputFileStream.Close()
    $inputFileStream.Close()

    # Optionally delete the original file
    if ($DeleteOriginal) {
        Remove-Item $InputFilePath -Force
    }
}

# Begin main

function Invoke-EncryptionSimulator {

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $false)]
        [Alias("td")]
        [String]
        $targetDir = $null,

        [Parameter(Mandatory = $false)]
        [Alias("a")]
        [String]
        $Action = "Encrypt",

        [Parameter(Mandatory = $false)]
        [Alias("k")]
        [String]
        $aesKey = $null,

        [Parameter(Mandatory = $false)]
        [Alias("i")]
        [String]
        $aesIv = $null,

        [Parameter(Mandatory = $false)]
        [Alias("l")]
        [int]
        $LogLimit = "0",

        [Parameter(Mandatory = $false)]
        [Switch]
        $DeleteOriginal = $false,

        [Parameter(Mandatory = $false)]
        [Switch]
        $DisableLog = $false,

        [Parameter(Mandatory = $false)]
        [Switch]
        $Unattended = $false

    )

    # Prevent deletion of original files if using decrypt
    if ($DeleteOriginal -like $True -And $Action -match "decrypt") {
        $DeleteOriginal = $False
    }

    # Start logging
    time
    if ($DisableLog -eq $false) {
        $logName = "Invoke-EncryptionSimulation-Log-"
        $logFile = "$logName" + "$time" + ".txt"
        # Check to see if the log limit has been set and clean up
        if ($LogLimit -ge 1) {
            Get-ChildItem -File "$logName*" | Sort-Object -Property CreationTime | Select-Object -SkipLast $LogLimit | Remove-Item
        }
        Start-Transcript -Path $logFile
    } else {
        $logFile = "Disabled"
    }

    # Clear the screen
    clear

    # Hostname
    $hostname = $env:COMPUTERNAME
    # Working directory
    $workingDir = ($pwd).Path

    ""
    "+-------------------------------------------------------------------------------------"
    "| Invoke-EncryptionSimulator v0.2"
    "+-------------------------------------------------------------------------------------"
    ""
    "+-------------------------------------------------------------------------------------"
    "| Checking requirements..."
    "+---------------------------------"
    "|"
    # Verify target directory is set
    if ($targetDir -like $null) {
        $targetDir = Read-Host "| Please enter path for the target directory (ex - `"C:\users\user01\Desktop\TargetDir`")"
        "|"
    } else {
        "| Target directory specified: True"
        "| Specified target directory: $targetDir"
    }
    # Verify the target directory exists
    if (Test-Path -Path $targetDir) {
        "| Target directory exists: True"
        "|"
    } else {
        "| Target directory exists: False"
        "|"
        "| Please verify the directory and restart the script!"
        "|"
        "+-------------------------------------------------------------------------------------"
        Pause
        Stop-Transcript
        exit
    }
    # Check to see if the key/iv are set and generate a pair if not
    if ((-Not($aesKey)) -Or (-Not($aesIV))) {
        try {
            "| No key/iv specified, generating random pair..."
            $randomKey = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | % {[char]$_})
            $randomIV = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | % {[char]$_})
            $aesKey = b64-encode($randomKey)
            $aesIV = b64-encode($randomIV)
            "|"
            "+-------------------------------------------------------------------------------------"            
        } catch {
            "| Key generation failed!"
            "| Error message: $_"
            "|"
            "+-------------------------------------------------------------------------------------"
            Pause
            Stop-Transcript
            exit
        }
    }

    # Gather the initial target directory stats
    targetDirStats

    # Admin check
    $isUserAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    ""
    "+-------------------------------------------------------------------------------------"
    "| Script execution info..."
    "+---------------------------------"
    "|"
    "| Start time: $time"
    "|"
    "| Hostname: $hostname"
    "| Script running as Admin: $isUserAdmin"
    "| Current working directory: $workingDir"
    "| Log file: $logFile"
    "| Log limit: $logLimit"
    "|"
    "| Target directory: $targetDir"
    "| Target directory stats: Directories - $dirStatsCount Files - $fileStatsCount"
    "| Action: $Action"
    "| Key: $aesKey"
    "| IV: $aesIv"
    "| Delete original file: $DeleteOriginal"
    "| Unattended: $Unattended"
    "|"
    "+-------------------------------------------------------------------------------------"
    ""
    "+-------------------------------------------------------------------------------------"
    "| WARNING - Please review/verify all of the information above before proceeding!"
    "+---------------------------------"
    "|"
    # Check to see if we are running in unattended mode
    if ($Unattended -eq $false) {
        # Attended mode
        "| Are you sure you want to continue?"
        $noTurningBack = Read-Host -Prompt "| Yes or No"
        if($noTurningBack -like "No") {
            "|"
            "| Canceling..."
            "|"
            "+-------------------------------------------------------------------------------------"
            Pause
            Stop-Transcript
            exit    
        } 
    } else {
        # Unattended mode - auto answer yes
        $noTurningBack = "Yes"
        "| Running in unattended mode - Skipping final check..."
    } 

    if ($noTurningBack -like "Yes") {
        "|"
        "| Proceeding in 10 seconds..."
        Start-Sleep -Seconds 7
        "| Three........."
        Start-Sleep -Seconds 1
        "| Two......"
        Start-Sleep -Seconds 1
        "| One..."
        Start-Sleep -Seconds 1
        "|"
        "| Go time!"
        "|"
        "+-------------------------------------------------------------------------------------"
    } else {
        "| Please type Yes or No!"
        "|"
        "+-------------------------------------------------------------------------------------"
        Pause
        Stop-Transcript
        exit  
    }
    ""
    if (($action -match "encrypt") -Or ($action -match "decrypt")) {
        "+-------------------------------------------------------------------------------------"
        "| Beginning encryption/decryption..."
        "+---------------------------------"
        "|"
        $actionCompleted = -join("$action","ed")
        # Loop through each file in the directory
        Get-ChildItem -Path $targetDir -File -Recurse | ForEach-Object {
            # If the action is encrypt and the target filename already contians encrypt, skip it.
            if ($_ -match "`.encrypted" -And $_ -notmatch "`.decrypted" -And $action -match "encrypt") {
                "| Skipping, file appears to be encrypted - $_"
                "|"
            }
            
            if (($_ -match "`.encrypted" -And $_ -notmatch "`.decrypted" -And $action -match "decrypt") -Or ($_ -notmatch "`.encrypted" -And $_ -notmatch "`.decrypted" -And $action -match "encrypt")) {
                # Construct output file path
                $outputFilePath = -join($_.FullName,"`.$actionCompleted")
                "| $action - $_ `> " + $_ + "`.$actionCompleted"
                # Encrypt or decrypt each file
                Try {
                    Encrypt-Decrypt-File -InputFilePath $_.FullName -OutputFilePath $outputFilePath -Key $aesKey -IV $aesIv -Action $action -DeleteOriginal $DeleteOriginal
                    "|"
                } Catch {
                    "| Something went wrong!"
                    "| Error message: $_"
                    "|"
                }
            }
        }
    }
    if ($action -match "restore") {
        "+-------------------------------------------------------------------------------------"
        "| Beginning restore..."
        "+---------------------------------"
        "|"
        RestoreFiles
    }
    if ($action -match "cleanup"){
        "+-------------------------------------------------------------------------------------"
        "| Beginning cleanup..."
        "+---------------------------------"
        "|"  
        DeleteFilesByExtension -Extensions @(".encrypted", ".decrypted")
    }
    # Gather the initial target directory stats
    targetDirStats
    # Get the finish time
    time
    "| Script complete!"
    "|"
    "| Post run stats: Directories - $dirStatsCount Files - $fileStatsCount"
    "| Finish time: $time"
    "|"
    "+-------------------------------------------------------------------------------------"
    #Stop logging
    Stop-Transcript
}
