# smstools

A bunch of scripts for looking at miscellaneous Nintendo game data files. Originally built for Super Mario Sunshine, but they also work well with The Legend of Zelda: The Wind Waker. Some support for the later-generation 3D games like Mario Galaxy.

* *bmd_blender and bck_blender:* Blender importers for BMD/BDL model files, BMT materials, and BCK animations. They're basically just Python ports of [http://www.amnoid.de/gc/](BMDView) (complete with comments!). Animations are currently restricted to linear interpolation only, and materials are rough approximations, not full shaders. Make sure common.py and texture.py are in the Python path somewhere (like blender/2.xx/scripts/addons/modules/)
* *bcsv.py:* Rudimentary Python2 command-line script for dumping strings from BMT and BCT table files.
* *bfn.py:* Python command-line script for dumping BFN bitmap fonts (requires PIL or Pillow).
* *blo.py:* Script for BLO layout files. BLO are used for GUI things like the HUD and menus. This tool makes HTML from them, and references images dumped with bti.py.
* *bmg.py:* BMG files are for localized strings. Some are used for subtitles in cutscenes; the script will make Subrip files out of those, and TXT dumps of anything else.
* *brfnt.py:* Like BFN, for later games.
* *brres.py:* Images/textures, but I'm not sure anymore where from.
* *bti.py:* Texture files, without bitmaps, usually used for GUI elements. Dumps to both PNG (PIL) and DDS (non-standard formats, but also probably incorrect sometimes)
* *col_blender:* Blender importer for COL file collision data. Also started from thakis' colview.
* *ral.py:* Unknown. Just strings so far.
* *scene.bin.py:* In Sunshine, map layouts are stored in hierarchical "scene.bin" files. There are a few other .bin files for other things. This script is very old and very messy, but can theoretically dump the scene info to console, import it into Blender (not an addon, run it directly from script view), or put it into a VMF Source engine map.
* *sequence-com.py:* BMS files and COM files (extracted from aaf, see wwdumpsnd) are MIDI-like note sequences (.scom is for sfx indexing, I'm guessing). This script translates them into real MIDI.
* *tpl.py:* Like BTI, for later games. These files can actually have multiple images collected inside, but I'm guessing that's either a mistake or a glitch in the decompressor I was using.
* *wwdumpsnd:* hcs's (https://www.hcs64.com/vgm_ripping.html)[wwdumpsnd], significantly expanded through disassembly/debugger stepping, to support more than just dumping the WAVes. Still lots to expand on.
* *ymap.py:* Sunshine maps also usually com with a ymap.ymp file which is a grayscale heightmap of the level. This dumps that to an image as well as the dimensions.
* *common.py and texture.py:* Common library functions required by most of the Python scripts.

LICENSE:

bmd_blender, bck_blender, col_blender, wwdumpsnd, and possibly others are directly based on the work of other people. I don't know what the original licenses were, so I can't say if these can be freely distributes. But I also assume you're probably not going to use these comercially, anyway.
