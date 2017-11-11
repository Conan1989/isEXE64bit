<# determine whether or not an .exe on file is 64 ot 32 bit

Example usage:
fooisEXE64bit -FilePath "C:\Temp\npp.7.5.1.bin.x86\notepad++.exe"
False

fooisEXE64bit -FilePath "C:\Temp\npp.7.5.1.bin.x64\notepad++.exe"
True
#>


function fooisEXE64bit
    {
        [CmdletBinding()]
        param (
                [parameter(Mandatory=$true)][ValidateScript({(Test-Path -Path $PSItem) -and ($PSItem -like "*.exe")})][String]$FilePath
              )
        
        [int32]$MACHINE_OFFSET = 4
        [int32]$PE_POINTER_OFFSET = 60

        [byte[]]$data = New-Object -TypeName System.Byte[] -ArgumentList 4096
        $stream = New-Object -TypeName System.IO.FileStream -ArgumentList ($FilePath, 'Open', 'Read')
        $stream.Read($data, 0, 4096) | Out-Null

        [int32]$PE_HEADER_ADDR = [System.BitConverter]::ToInt32($data, $PE_POINTER_OFFSET)
        [int32]$machineUint = [System.BitConverter]::ToUInt16($data, $PE_HEADER_ADDR + $MACHINE_OFFSET)


        Switch ($machineUint) 
            {
                0x014c {return $false}
                0x8664 {return $true}
            }
    }
