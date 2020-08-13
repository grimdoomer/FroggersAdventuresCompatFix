# Frogger's Adventures Compatibility Fix
This is an unofficial patch for Frogger's Adventures to fix Windows XP SP3/Vista/7/8/10 compatibility issues.  
More specifically, any computer which had received an update after approximately 2007/2008 was unable to run this game.  

## Screenshot
![It works!](https://raw.githubusercontent.com/grimdoomer/FroggersAdventuresCompatFix/master/_repo/screenshot.png)

## Information
For information regarding how these patches actually fix the game, read the source code.  
There are two different patches included in this repository.  

**Assembly Patch:**  
This is the patch that your average person (who just wants to play the game) should use.  
It's a conversion of the detours patch, but made to be just a simple drag and drop fix.  
This is easier/more intuitive for the user, but it's harder for us to work with, since we're writing it in x86 Assembly.  
The source code is contained in a single file, [Frogger.asm](https://github.com/grimdoomer/FroggersAdventuresCompatFix/blob/master/Frogger.asm).  
In order to apply this patch, you will need to use [XePatcher](https://web.archive.org/web/20200813054545/http://icode4.coffee/files/XePatcher_2.7.zip)

**Detours Patch:**  
This patch will likely be more useful for developers, or anyone who wants to make changes.  
This patch is in C++, and works by using Detours to have a separate launcher for the game `SwampLauncher.exe`, which loads the real game executable, then injects changes (`Swampy.dll`) into the process. The nice thing about this is that it allows writing C++ code instead of assembly.  
However, for the average user, the `Assembly Patch` is likely the better option.  

## Information & Help
For help or information on this patch, or information regarding data modding, check out both the Highway Frogs [website](http://highwayfrogs.net/) and [discord server](http://discord.gg/GSNCbCN).  
Pull requests are welcome, if you have anything to contribute.  

## Other
Authors:
 - Grimdoomer (Figuring out why the game didn't work, Detours Patch, XePatcher, x86 Guru)
 - Kneesnap (Detours Patch, Assembly Patch / Patched Exe)

Future Wants:  
 - A delta-time fix that doesn't involve locking the framerate to 60FPS. It seems like the higher the framerate, the more broken things get. (See: The catfish in level 1 running at 250FPS vs 650FPS) The 60FPS cap has noticeable stutter when compared to the uncapped version, even if it's minor.  
 - 