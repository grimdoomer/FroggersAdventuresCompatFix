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

## Troubleshooting
In rare cases the game may fail to start if it can't set your display to 640x480 resolution. This may happen because your graphics card does not have a profile setup for 640x480 resolution. Most modern greaphics cards should have some sort of control panel that will allow you add 640x480 as a custom resolution profile which will allow the game to run correctly.

For NVIDIA graphics cards you can open the NVIDIA Control Panel application and follow these steps:
1. Click on "Change Resolution" under "Display"
2. Select your display and click the "Customize" button
3. Make sure "Enable resolutions not exposed by the display" is checked and click the "Create Custom Resolution" button
4. Set the new resolution to 640x480 and 32 for color depth
5. Hit the "Test" button and if everything is okay save your changes
6. Relaunch the game and it should now start and display properly.
![](/_repo/resolution.png)

For other graphics card manufactures please search google for how to add custom resolutions for your card.

## Information & Help
For help or information on this patch, or information regarding data modding, check out both the Highway Frogs [website](http://highwayfrogs.net/) and [discord server](http://discord.gg/GSNCbCN).  
For the technical details behind how the patch was developed and what it does, check out [this blog post](https://icode4.coffee/?p=224).  
Pull requests are welcome, if you have anything to contribute.  

## Other
Authors:
 - Grimdoomer (Figuring out why the game didn't work, Detours Patch, XePatcher, x86 Guru)
 - Kneesnap (Detours Patch, Assembly Patch / Patched Exe, Some reverse engineering)
