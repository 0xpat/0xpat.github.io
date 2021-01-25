---
layout: post
title: Abusing COM objects
---

## Quick introduction
Component Object Model is a Windows binary interface for inter-process communication. Communication is performed in a form of client-server interaction - a client can call methods provided by a COM object (acting as a server) by referencing the COM object by pointer or reference.  
Applications can implement COM interface in multiple ways - the bottom line is that the binary (compiled) object must provide methods for other processes to interact with. Such methods can be used for anything - for example, MS Office applications serve interfaces (APIs) for document creation, manipulation etc.  
COM classes can be identified by CLSID or name. COM object is of course an instance of specific COM class.

## Abuse
Several COM objects provide some interesting (for an attacker) methods which can be used file and process creation or command execution. There are publicly known and exploited objects and methods. Even more interesting is DCOM interface which is an extension of COM that allows interaction with remote processes using RPC. It's just great - you can create an instance of an object on a remote machine and then call some method to execute code remotely.  
However this article is about local COM abuse - we will try to find and explore objects facilitating local code execution. Such COM objects are sometimes used by threat actors or red teamers, for example in VBA macros.  

## Finding useful COM classes
I decided to browse COM classes available on the default Windows (Server 2012) installation to find any interesting objects. Similar concept was described on FireEye blog some time ago.  
The technique I used is quite straightforward:  
1. Enumerate all CLSID, e.g. using [ComPower](https://github.com/Kriegel/ComPower) tool.
2. Attempt to instantiate all enumerated objects, one at a time - using `[System.Activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))` PowerShell method.
3. For each created object enumerate its properties and methods (`$object | Get-Member`). Then recursively (DFS-like) enumerate properties and methods of each property.
However I encountered some caveats - mainly recursion 'traps' when an object property was of the same type as the object (e.g. `{CLSID}.Document.Document.Document(...)` and so on). Anyway, after some tweaks applied to the script I was able to enumerate lots of objects. Output file had 2 million lines - each represented some object property or method.
4. Grep results for interesting names, such as "Shell", "Execute", "Create", "Run", "Exec" etc.  

After long manual analysis I was left with only a few useful methods - unfortunately I didn't discover anything new:  
⋅ **MMC20.Application** `{49b2791a-b1ae-4c90-9b8e-e860ba07f889}`  
⋅ **WScript.Shell** - `{72c24dd5-d70a-438b-8a42-98424b88afb8}`, `{f935dc22-1cf0-11d0-adb9-00c04fd58a0b}`  
⋅ **ShellBrowserWindow** - `{c08afd90-f2a1-11d1-8455-00a0c91f3880}`  
⋅ **Shell.Application** - `{13709620-c279-11ce-a49e-444553540000}`  
  
  
![mmc.exe and notepad.exe](../images/2020-3-10-Abusing_COM_Objects/mmc_notepad.gif "mmc.exe and notepad.exe"){: .center-image }  
*Interesting fact: when you use "MMC20.Application" COM object to start a process, its parent is "mmc.exe" and not "powershell.exe" or "excel.exe" as one could suppose.*  

I also identified several methods that can be (ab)used for HTTP requests and file download:  
⋅ **InternetExplorer.Application** - `{0002df01-0000-0000-c000-000000000046}`, `{d5e8041d-920f-45e9-b8fb-b1deb82c6e5e}`  
⋅ **WinHttpRequest** - `{2087c2f4-2cef-4953-a8ab-66779b670495}`  
⋅ **Shell.Explorer** - `{8856f961-340a-11d0-a96b-00c04fd705a2}`, `{eab22ac3-30c1-11cf-a7eb-0000c05bae0b}` (I was unable to test this one).  

## Summary
Built-in features analysis can sometimes yield interesting findings - new techniques for code execution, lateral movement etc. may be identified. Unfortunately this was not the case at this time. It might be a good idea to focus on custom COM classes registered by third-party software - that's definitely something worth trying.  
Anyway, COM objects remain an interesting code execution method.
