# Debloat Windows
An edit on Chris Titus Tech's Debloater Script

Use the following command to debloat windows:

powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://git.io/JTrqX')"

##########
# Tweaked Win10 Initial Setup Script
# Primary Author: Disassembler <disassembler@dasm.cz>
# Primary Author Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
# Tweaked Source: https://gist.github.com/alirobe/7f3b34ad89a159e6daa1/
#
#    Note from author: Never run scripts without reading them & understanding what they do.
#
#	Chris Titus Tech Additions:
#
#	- Dark Mode
#	- One Command to launch and run
#	- Chocolatey Install
#	- O&O Shutup10 CFG and Run
#	- Added Install Programs
#	- Added Debloat Microsoft Store Apps
#	- Added Confirm Menu for Adobe and Brave Browser
#	- Changed Default Apps to Notepad++, Brave, Irfanview, and more using XML Import feature (Removed by Gam3less due to new browsers)
#
#	Gam3less Additions:
#
#	- Pick Browser and install from Brave, Firefox or Google Chrome
#	- Customized and removed over 1400 lines of code
#	- Changed one command to run this script
##########
 
