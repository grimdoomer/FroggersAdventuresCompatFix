# Frogger's Adventures Compatibility Fix
This is an unofficial patch for Frogger's Adventures to fix Windows XP SP3/Vista/7/8/10 compatibility issues.  
More specifically, any computer which had received an update after approximately 2007/2008 was unable to run this game.  

## Screenshot
![](/_repo/screenshot.png)

## Information
For information regarding how these patches actually fix the game, read the source code.  
There are two different patches included in this repository.  
 
### Assembly Patch  
This is the patch that your average person (who just wants to play the game) should use.  
It's a conversion of the detours patch, but made to be just a simple drag and drop fix.  
This is easier/more intuitive for the user, but it's harder for us to work with, since we're writing it in x86 Assembly.  

**How to use:**  
1. Download and extract [this file](https://github.com/grimdoomer/FroggersAdventuresCompatFix/releases/download/1.0.0/Frogger.s.Adventures.Patch.v1.0.0.zip).  
2. Find your Frogger installation folder. (Usually `C:\Program Files (x86)\Konami\Frogger's Adventures\`)  
3. Replace the original `FrogADV.exe` file with the one in the zip file you downloaded.  
4. Enjoy!

**Information For Developers:**
The source code is contained in a single file, [Frogger.asm](https://github.com/grimdoomer/FroggersAdventuresCompatFix/blob/master/Frogger.asm).  
In order to compile this patch, you will need to use [XePatcher](https://web.archive.org/web/20200813054545/http://icode4.coffee/files/XePatcher_2.7.zip)

## Detours Patch   
This patch will likely be more useful for developers, or anyone who wants to make changes.  
This patch is in C++, and works by using Detours to have a separate launcher for the game `SwampLauncher.exe`, which loads the real game executable, then injects changes (`Swampy.dll`) into the process. The nice thing about this is that it allows writing C++ code instead of assembly.  
However, for the average user, the `Assembly Patch` is likely the better option.  

**How to use:**
1. Download and extract [this file](https://github.com/grimdoomer/FroggersAdventuresCompatFix/releases/download/1.0.0/Frogger.s.Adventures.Patch.v1.0.0.zip).  
2. Find your Frogger installation folder. (Usually `C:\Program Files (x86)\Konami\Frogger's Adventures\`)  
3. Copy `Swampy.dll` and `SwampLauncher.exe` into the game installation folder.  
4. To run the game, double click `SwampLauncher.exe`.  

## Information & Help
For help or information on this patch, or information regarding data modding, check out both the Highway Frogs [website](http://highwayfrogs.net/) and [discord server](http://discord.gg/GSNCbCN).  
Pull requests are welcome, if you have anything to contribute.  

## Other
Authors:
 - Grimdoomer (Figuring out why the game didn't work, Detours Patch, XePatcher, x86 Guru)
 - Kneesnap (Detours Patch, Assembly Patch / Patched Exe, Some reverse engineering)
