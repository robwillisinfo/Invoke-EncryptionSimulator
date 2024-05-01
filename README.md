![Invoke-EncryptionSimulator](https://raw.githubusercontent.com/robwillisinfo/Invoke-EncryptionSimulator/main/Invoke-EncryptionSimulator.png)

# Synopsis
Invoke-EncryptionSimulator is designed to be a simple and safe way to emulate the encryption stage of a  ransomware deployment to aid in development and testing of controls focusing on file system level  changes rather than process related telemetry.

# Description
Invoke-EncryptionSimulator is designed to be a simple and safe way to emulate the encryption stage of a 
ransomware deployment to aid in development and testing of controls focusing on file system level 
changes rather than process related telemetry. No additional scripts or modules are neeeded, everything 
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
  - If the action is cleanup, delete all the files ending with either .encrypted or .decrypted
- Wrap up, stop logging

# Examples

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

Destructive - Restore all the decrypted files to their original filename/extension (removing the .decrypted):  
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Restore  

Stage 4 - Cleanup  

Delete all left over .Encrypted and/or .Decrypted files:  
C:\PS> Import-Module .\Invoke-EncryptionSimulator.ps1; Invoke-EncryptionSimulator -targetDir "C:\User\User01\Desktop\Test" -Action Cleanup  

