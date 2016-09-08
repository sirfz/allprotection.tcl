###########################[ ALL PROTECTION 4.9b4 ]##########################
#                                                                           #
# Author  : Opposing a.k.a Sir_Fz (Fayez Zouheiry)                          #
# Version : 4.9b4                                                           #
# Released: September 08, 2016                                              #
# Source:   https://github.com/sirfz/allprotection.tcl                      #
##                                                                          #
# Description: Has all kinds of channel protections + Botnet channel flood  #
#              protections and private protections.                         #
#                                                                           #
# Commands:                                                                 #
#          DCC:                                                             #
#              .ap:import <oldchan> <*/newchan> (This sets the AP settings  #
#               of <oldchan> on <newchan> or all chans if *)                #
#              .ap:reset <*/chan> (This will reset the AP settings of chan  #
#               or all chans if * to the default settings)                  #
#              .ap:disable <*/chan> (This will disable all protections on   #
#               chan or all chans if *)                                     #
#              .ap:monitor (displays info about followed punishments)       #
#              .ap:add <list> <chan/global> <elements>                      #
#              .ap:rem <list> <chan/global> <elements>                      #
#              .ap:list <list> <chan/global>                                #
#              .ap:priv <set/list> <setting> <value> (priv flood settings)  #
#          ** Available lists: bchans, bnicks, bidents, bwords, adexempts,  #
#             droneexempts, adwords, bctcrs & greetexempts.                 #
#                                                                           #
#          All protections are enabled via .chanset DCC command.            #
#          Use: .chaninfo to know AllProtection's settings (ap:<setting>)   #
#          NOTE: To set an AP channel setting use: (* means all channels)   #
#                .chanset <chan> <setting> <value> <btime> <punish> <btype> #
#                                                                           #
# Credits:                                                                  #
#         - Thanks to my friend Salah Rifai who introduced me to Eggdrops   #
#         & *nix. He is the person who guided me to Eggdrops' resources. He #
#         also was the founder of nexushells.net which was my first shell   #
#         which hosted my Eggdrop (Shrider).                                #
#         - Thanks to http://forum.egghelp.org which was and still is my    #
#         tcl toutor, I've learned tcl through this community.              #
#         - Thanks to slennox for adding a link on the main page of         #
#         www.egghelp.org to the topic of AllProtection, and for hosting    #
#         the script on his site when my site went down.                    #
#         - Thanks Silence, Marcel, dotslasher & others for reporting bugs  #
#         which was an important step for the developement of this script.  #
#         - Thanks to all who suggested ideas & features at egghelp.org.    #
#         - Used maskhost & wordwrap procs by user from the egghelp forum.  #
#         Edited wordwrap slightly to suite its purpose in the script.      #
#         - Used massmode proc's algorithm for ban-queueing (by user).      #
#         - Used checkbcd proc by Marcel (edited by me).                    #
#                                                                           #
# History:                                                                  #
#         - 4.9b4: Eggdrop 1.8 compatibility (working Antispam bot).        #
#         - 4.9b3: bad nicks on nick-change punishment fixed. fixed         #
#           punishment execution. Minor optimizations.                      #
#         - 4.9b2: fixed bug introduced in 4.9b regarding clones count in   #
#           kick messages.                                                  #
#         - 4.9b: Added bk punishment (ban then kick). Code formatting and  #
#           cleanup + some optimizations.                                   #
#         - 4.8: Updated contact information and LICENSE file. Centralized  #
#           version number.                                                 #
#         - 4.7: Stable release of the 4.6 series. Got the bad nicks/idents #
#           & perhaps other fixes I haven't logged. It was a good ride :)   #
#         - 4.6b9: The script would not ban if a channel was not added in   #
#           lower case; fixed now. Fixed other issues...                    #
#         - 4.6b8: Integrated queues, enhanced AntiSpamBot, modulated       #
#           exempt types, scanning bad/excess chans and bad CTCP replies    #
#           when bot gains ops, flexible warn method (notice or privmsg),   #
#           fixed AntiSpamBot IP problem, added ability to exempt hostmasks #
#           from greets by antispambot, AntiSpam bans spammers only if on   #
#           chan (optional), ability to immediately ban thru X, enable or   #
#           disable bad words/ads ban for quit/part, queue for bad/excess   #
#           chans scan. Punish bad chan users in all channels.              #
#         - 4.6b7: Throttle kicking (halt redundant kicks). Bad words/ads   #
#           now detected in notices, parts & quits. Choose CTCP requests 4  #
#           bad ctcp replies (bad version before). Ability to ban thru X.   #
#           Following now occurs in 1 array (less memory). All flood types  #
#           now have a punishment method. Added AntiSpamBot. Enhancements   #
#           made over code.                                                 #
#         - 4.6b6: Adding drone exempts via .ap:add cmd. Fixed undiscovered #
#           exploit in string splitting (string2list). Added extra 2 ban    #
#           types. Added exemption for part msgs in revdoor protection.     #
#           Bad version-reply kick, set private flood settings via DCC, log #
#           everyday (configurable), scan channels in intervals for bad or  #
#           excess chans or bad version-replies and ability to add custom   #
#           advertising words.                                              #
#         - 4.6b5: Fixed bugs in badchan and clones protections. Enhanced   #
#           advertisement detection to avoid false detections.              #
#         - 4.6b4: Fixed lists saving, uninstalling error. Added ability to #
#           remove bans on full banlist + enhanced the drones detecting     #
#           procedure and the ap:import DCC command to accept *.            #
#         - 4.6b3: More code fixes and enhancements. You can now add words  #
#           to be exempted from advertising (channel specific as well) and  #
#           log bot's kicks and bans. Join flood can now check joins from   #
#           same idents if enabled. Implemented queueing bans.              #
#         - 4.6b2: Major coding changes, changed style of binding and procs #
#           for better and faster performance. Reduced code & implemented   #
#           the use of namespaces in order not to conflict with other       #
#           scripts. Added excess chans protection + several bug fixes.     #
#         - 4.6b1: Major coding changes, added bad chans protections + bug  #
#           fixes.                                                          #
#                                                                           #
# Report bugs/suggestions at https://github.com/sirfz/allprotection.tcl     #
#                                                                           #
# Copyright © 2005-2016 Opposing (aka Sir_Fz)                               #
#                                                                           #
# This program is free software; you can redistribute it and/or modify      #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation; either version 2 of the License, or         #
# (at your option) any later version.                                       #
#                                                                           #
# This program is distributed in the hope that it will be useful,           #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with this program; if not, write to the Free Software               #
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  #
# USA.                                                                      #
#                                                                           #
#############################################################################
#

########################
#   SETTINGS & iNFO    #
########################

### READ THIS FIRST:
# * AllProtection works best with eggdrop1.6.18 and above. (so upgrade)
#
# * AllProtection exempts channel ops, friends (+f) and masters (+mo) from protection by default.
# That means users with the +f or +mo flags will not be affected by any protection.
# (You can add hosts to the +f handle if you don't want the bot to ban them). To prevent from banning
# ChanServ, add chanserv to your bot with the +f or +mo flag.
#
# * AllProtection does not use the internal banlist of the bot so you will not have to worry
# about other ops not being able to remove the bans, they can! (feature or bug, I dont care :P)
#
# * AllProtection will not trigger protection on a channel where the bot is not oped, so your
# bot will not send redundant commands to the server. (good for the lag)
#
# * AllProtection strips control-codes (i.e. bold, underline, colors...etc) from text when checking for
# repeats, bad words or advertising.
#
# * All settings are enabled via .chanset DCC command. Example: .chanset #channel ap:textl 5:2 15 w:k:kb 2
# this will enable the text flood (lines) protection on #channel (punish on 5 lines or more in 2 seconds)
# 1st warn - 2nd kick - 3rd kickban. ban is 15 minutes and ban type is 2.
#
# * You can use mode lock modes such as "mR-k type.flood" which will work fine with AllProtection.
#
# * Adding elements to the lists (bad words, chans...etc) can ONLY be done via the DCC commands.
#
# * Read all the comments during configuration so you won't miss any important info.
### Enjoy configuring...

# You can change the name of the namespace (AllProtection).
namespace eval AllProtection {

## Basic declarations: (don't touch)
variable declr
foreach declr {textl textc notcl notcc capsp repeatf codesf adexempts adwords greetexempts adv antispam bwords
    swear ctcpf massdeop massdeop masskick massb joinflood pmsgf revdoor nickflood eclones bnick bnicks drone
    bident bidents droneexempts bchans bchan bctcrs bctcr apfp ptextl ptextc pnotil pnotic pctcpf NumKicks apudef
    apqueue banthruX ap:udefs logkbs btclocked kckcount cbcd serv kline kcfop} { variable $declr }
unset declr
# Eggdrop version compatibility settings
variable _EGGDROP_1_8 1080000
if {$::numversion >= $_EGGDROP_1_8} {
    variable _vhost4 $::vhost4
    variable _vhost6 $::vhost6
    variable _hostname $_vhost4
} {
    variable _vhost4 ${::my-ip}
    variable _vhost6 "" 
    variable _hostname ${::my-hostname}
}
## Basic declaraions complete

##############################
# Configurations start here: #
# __________________________ #

# Do you want your bot to queue bans? set here the time in seconds before dumping bans:
# NOTE: 0 means the bot will set the ban immediately
# The modes-per-line setting in eggdrop.conf is the number of modes allowed per command.
set apqueue(time) 1

# Set here the numbers of last bans to be removed on full banlist? (0: remove none)
# NOTE: Full banlist is when the channel has max-bans bans set. (from eggdrop.conf)
variable removebs 20

# Do you want the bot to ban through services?
# 0: Never
# 1: Only when banlist is full (determined by max-bans)
# 2: always
set banthruX(do) 0

# If banthruX is 1/2, set the command here to ban through services:
# %nick = nickname
# %ban = ban-mask
set banthruX(cmd) "privmsg X :ban %chan %ban %btime %level %reason"

# If banthruX is 1/2, set here the default level to be used on all channels
lappend ap:udefs {ap:level 75}

# Do you want AP to log all the kicks/bans done by the bot? (0: no, 1: daily, 2: forever)
set logkbs(do) 0

# If yes, set the logfile here: (will be reset everyday at 3:00 a.m.)
set logkbs(file) "logs/aplogs.log"

# Set here any additional exempts, you can exempt the following:
# ops: Channel ops
# halfops: Channel halfops
# voices: Channel voices
# +flags|+flags: Users with global or channel specific flags (e.g. +fm friends and masters...)
# -flags&-flags: Users which do not have the specified flags (e.g. -k&-k)
variable exmptype {ops voices +fmo|+fmo}

# Set here the handles of the users you want to notify when the bots locks a channel
# for mass (botnet) flood.
# example: set notifyusers {TheOwner LamerDude}
variable notifyusers {}

# Set here the notice to be sent to the channel when the bot locks the channel because of a
# Botnet flood. leave "" if you don't wish the notice to be sent.
set btclocked(lnotc) "Channel has been locked due to flood, sorry for any inconvenience this may have caused."

# What info do you wanna add to your kick message?
# After setting this variable, you can use $kckcount(form) to add a these info to the bot's
# kick msg.
### NOTE:
## %kcount = number of kicks.
## %btime = ban time
## %chan = channel name
## %date = kick date
## %rate = offenses in seconds, bad words/nicks/idents/chans/ads or clone/clones (depends on type of offense)
### PS: You can use the above directly in the kick message (not only here)
set kckcount(form) "(%rate) :: \[%date\] - Banned %btime minutes ·%kcount·"

# Set the file in which the number of kicks will be stored.
set kckcount(file) "scripts/kcount.txt"

# Do you want the bot to check for bad nicks/idents and clones when it first joins the channels
# and gains op ? (0: no , 1: yes)
# NOTE: This may be CPU intensive if your bot is on big channels or on alot of channels.
# NOTE: This may (probably will) cause huge self-lag on the bot.
set cbcd(check) 0

# If cbcd(check) is set to 1, change this if you want the bot to only check for certain types
# of protection in the nicklist.
# drones : Random drones
# clones : Excess clones and kick them
# bnicks : Bad nicks
# bidents: Bad idents.
# bchans : Bad/Excess channels.
# bctcrs : Bad CTCP replies
set cbcd(procs) {drones clones bnicks bidents bchans bctcrs}

# If cbcd(check) is set to 1, on what channels do you want it to be applied ? (use "*" to make it work on all chans)
# example: set cbcd(chans) "#chan1 #chan2"
set cbcd(chans) "*"

# Your service's chanserv nick.
# example: set serv(nick) "ChanServ" or "PRIVMSG X@channels.undernet.org"
set serv(nick) "ChanServ"

# Chanserv deop command.
# use %nick for the nick you want to deop and %chan for the channel name.
# example: set serv(deop) "deop %chan %nick"
set serv(command) "deop %chan %nick"

# Set the time in seconds to wait before reseting the punishment monitor:
# Note: this setting means the bot will apply the punishment steps on each user
# within this period of time, otherwise it'll trigger steps from the beginning.
variable pwait 180

# Set here the warning method you wish to use: (PRIVMSG or NOTICE)
variable wmeth NOTICE

# Edit this only if your bot is an ircop and will use the kline command:
# Set here the kline command used on your server.
# for example some ircds user:
# kline %mask %time %reason
# others use:
# kline %time %mask %reason
## NOTE:
# %mask = the klined mask.
# %time = the kline time.
# %reason = the kline reason.
##
set kline(cmd) "kline %time %mask :%reason"

# set the default kline time. (seconds or minutes depends on your ircd)
set kline(time) 30

## Available punishment methods:
# v  : Void - do nothing
# w  : Warn offender
# k  : Kick offender
# b  : Ban offender
# kb : Kick + Ban offender
# bk : Ban + Kick offender
# kl : KLine offender
# kil: Kill offender
#
## You can use them like this for example:
# w:k:kb
# this means, first Warn then Kick then Kickban. (if offence is repeated ofcourse)
## these steps will be triggered if the offences happend during <pwait> seconds.
# NOTE: These methods are not applicable on all flood types. I only applied this
# feature on the flood types I think they're needed.

## Available ban types:
# 0 : *!user@full.host.tld
# 1 : *!*user@full.host.tld
# 2 : *!*@full.host.tld
# 3 : *!*user@*.host.tld
# 4 : *!*@*.host.tld
# 5 : nick!user@full.host.tld
# 6 : nick!*user@full.host.tld
# 7 : nick!*@full.host.tld
# 8 : nick!*user@*.host.tld
# 9 : nick!*@*.host.tld
# 10: *!user@*
# 11: nick!*@*

## Available kline mask types:
# 0 : user@full.host.tld
# 1 : *user@full.host.tld
# 2 : *@full.host.tld
# 3 : *user@*.host.tld
# 4 : *@*.host.tld
# 5 : user@full.host.tld
# 6 : *user@full.host.tld
# 7 : *@full.host.tld
# 8 : *user@*.host.tld
# 9 : *@*.host.tld
# 10: user@*

##########################
#      TEXT FLOOD        #
##########################

#
## 1 ## Text flood (lines)
#

# use .chanset #channel ap:textl <lines>:<seconds> <btime> <pmeth> <btype> (in DCC, 0:0 to disable)
# Set default rate here:
lappend ap:udefs {ap:textl "5:2 60 k:kb 2"}

# Text flood (lines) kick msg.
set textl(kmsg) "Text flood detected. $kckcount(form)"

# Text flood (lines) warn msg.
set textl(wmsg) "Warning: You've triggered text flood (lines) protection, slow down your typing."

## Edit the following only if you choose a punish method above 5 (oper commands):

# Text flood (lines) kline mask type.
set textl(ktype) 2

# Text flood (lines) kline/kill reason.
set textl(klmsg) "Text flooding is not permissable on this network."

# Text flood (lines) kline time (seconds or minutes depends on your ircd).
set textl(ktime) 0

#
## 2 ## Text flood (chars)
#

lappend ap:udefs {ap:textc "215:3 120 kb 2"}

set textc(kmsg) "Excess chars detected. $kckcount(form)"

set textc(wmsg) "Warning: You've triggered text flood (chars) protection, decrease your text legnth."

## Edit the following only if you choose a punish method above 5 (oper commands):

set textc(ktype) 2

set textc(klmsg) "Text flooding (chars) is not permissable on this network."

set textc(ktime) 0

#
## 3 ## Notice flood (lines)
#

lappend ap:udefs {ap:notcl "1:3 120 kb 2"}

set notcl(kmsg) "Notice not allowed. $kckcount(form)"

set notcl(wmsg) "Warning: you've triggered notice flood (lines) protection, slow down your notices."

## Edit the following only if you choose a punish method above 5 (oper commands):

set notcl(ktype) 2

set notcl(klmsg) "Notice flooding is not permissable on this network."

set notcl(ktime) 0

#
## 4 ## Notice flood (chars)
#

lappend ap:udefs {ap:notcc "200:3 180 kb 2"}

set notcc(kmsg) "Excess chars (notice) detected. $kckcount(form)"

set notcc(wmsg) "Warning: you've triggered notice flood (chars) protection, decrease your text length."

## Edit the following only if you choose a punish method above 5 (oper commands):

set notcc(ktype) 2

set notcc(klmsg) "Notice flooding (chars) is not permissable on this network."

set notcc(ktime) 0

###################
#      TEXT       #
###################

#
## 5 ## Caps flood.
#

# Use .chanset #channel ap:caps <percent>:<line-length> <btime> <pmeth> <btype> (in DCC, 0:0 to disable)
# Set default rate here:
lappend ap:udefs {ap:caps "60:90 120 kb 2"}

set capsp(kmsg) "Excess CAPS detected. $kckcount(form)"

set capsp(wmsg) "Warning: You've triggered caps flood protection, release your caps."

## Edit the following only if you choose a punish method above 5 (oper commands):

set capsp(ktype) 2

set capsp(klmsg) "Caps flooding is not permissable on this network."

set capsp(ktime) 0

#
## 6 ## Text repeating.
#

lappend ap:udefs {ap:repeatl "3:10 60 k:kb 2"}

## Text repeating Kick on how many consecutive repeated letters?
## Example: if this is set to 5 then the bot will kick any user who types (example):
# Hellooooo (5 consecutive o's)
# Hello!!!!!!!!! (5 and more consecutive ! marks)
## Use .chanset #channel ap:repeatc <number-of-letters> <btime> <pmeth> <btype> (in DCC, 0 to disable)
# Set default value here:
lappend ap:udefs {ap:repeatc "25 30 w:k:kb 2"}

set repeatf(kmsg) "Text repeating detected. $kckcount(form)"

set repeatf(lkmsg) "Letter repeats detected, do not use excess consecutive letters. $kckcount(form)"

set repeatf(wmsg) "Warning: You've triggered %type repeating protection, stop repeating."

## Edit the following only if you choose a punish method above 5 (oper commands):

set repeatf(ktype) 2

set repeatf(klmsg) "Constant repeating is not permissable on this network."

set repeatf(ktime) 0

#
## 7 ## Control codes.
#

# Use .chanset #channel ap:codes r:<n> b:<n> u:<n> c:<n> <btime> <pmeth> <btype> (in DCC)
# Example: If you set ap:codes to: r:35 b:35 u:35 c:35
# Then 35 (or more) characters affected by Reverse or Bold or Underline or Color
# will be considered an offence.
# Set default rate here:
lappend ap:udefs {ap:codes "r:35 b:80 u:80 c:80 90 kb 2"}

set codesf(kmsg) "Excess codes detected. $kckcount(form)"

set codesf(wmsg) "Warning: You've triggered control codes protection, release your msgs from codes."

## Edit the following only if you choose a punish method above 5 (oper commands):

set codesf(ktype) 2

set codesf(klmsg) "Excess use of control codes is not permissable on this network."

set codesf(ktime) 0

#
## 8 ## Advertising.
#

# NOTE: This protection also works for private advertising.

# Use .chanset #channel ap:adv + <btime> <pmeth> <btype> (to enable)
# set default value here: (+ enabled, - disabled)
lappend ap:udefs {ap:adv "+ 180 kb 2"}

# Set here the string you want to exempt (don't consider as spam):
# Note: %chan = current channel. Also, you can change these for every channel via DCC
# using the .ap:add command. (no wildcards used)
set adexempts(global) { %chan www.egghelp.org }

set adwords(global) { "*join *" "*plz visit*" }

set adv(kmsg) "Advertising detected. $kckcount(form)"

set adv(wmsg) "Warning: You've triggered adverting protection, advertisements are not allowed."

# ANTI SPAM BOT: (NOTE: Some networks may not allow such bots.)

# Use: .chanset #channel ap:antispam + <greet> <cycle-time> <idle-time> (to enable)
# the antispam bot will not cycle a channel where last join occured in <idle-time> or more minutes.
# <greet> is either + or - which will enable or disable the on-join message.
# set default value here:
lappend ap:udefs {ap:antispam "- + 10 10"}

# AntiSpamBot basic settings
# You can edit all these settings as you wish
# example: set antispam(nick) AntiSpamBot
set antispam(nick) $::altnick
set antispam(altnick) ${::altnick}1
# Antispam ident & real name
set antispam(user) AP
set antispam(realname) "AllProtection Anti-Spam"

##
# The following settings specify the desired vhost for your forked Antispam bot.
# Uncomment and edit these settings only if you wish to use settings other than
# you Eggdrop's defaults.
##
# Antispam bot's vhost (ipv4). Example: set antispam(vhost4) 127.0.0.1
#set antispam(vhost4) $_vhost4
# ipv6 (Eggdrop >= v1.8)
#set antispam(vhost6) $_vhost6
# hostname example: set antispam(hostname) my.lame.vhost.net (Eggdrop < v1.8)
#set antispam(hostname) $_hostname

# Ban spammer in all channels or only in channels it's in? (0: It's in, 1: All)
set antispam(banall) 1

# Exempt list from greets:
set greetexempts(global) { *example*!*@* *!*example*@*.example.net }

# If you want your bot to reply to users with random message, set messages here:
set antispam(r) {
    "hey, what's up"
    "I'm feeling good today, what about you ?"
    "I feel you're too busy ?"
    "Are you nice ?"
    "Hiiii lol"
    "hello there, just teasing"
}

# On what messages do you want the bot to reply:
set antispam(t) {
    "*hi*"
    "*h r u*"
    "*hello*"
    "*hola*"
    "*how *y*"
    "*how *u*"
    "*hey*"
    "*asl*"
    "*a/s/l*"
}

# Do you want the bot to msg users on join? (leave "" if no)
set antispam(greet) "Hello %nick, checking for spam. Please do not reply..."

# Stop greeting after how many joins in secs:
set antispam(jprot) 4:2

# Stop replying to messages after how many msgs in secs:
set antispam(mprot) 8:4

## Edit the following only if you choose a punish method above 5 (oper commands):

set adv(ktype) 2

set adv(klmsg) "Constant advertising is not permissable on this network."

set adv(ktime) 0

#
## 9 ## Swearing.
#

lappend ap:udefs {ap:swear "+ 120 kb 2"}

set bwords(global) {
    *fuck*
    "*bastard *"
    *cock*
    "* cunt *"
    *ommak*
    *fag*
    "* shit*"
    *asshole*
    *bitch*
    *pussy*
    "* whore *"
    "* slut *"
    *dickhead*
    *horny*
    "* shithead *"
    *fagget*
    "* dick? *"
    "* fag? *"
    "* fuker *"
    *penis*
    "* fuk *"
}

set swear(kmsg) "Bad word detected. $kckcount(form)"

set swear(wmsg) "Warning: You've triggered swearing protection, cussing is prohibited."

## Edit the following only if you choose a punish method above 5 (oper commands):

set swear(ktype) 2

set swear(klmsg) "Swearing is not permissable on this network."

set swear(ktime) 0

#
## 8-9 ## Swearing/Advertising in part/quit messages
#
# Exampl: "s:1 a:1" Enables banning of users with part/quit msgs containing swear/advertisement
lappend ap:udefs {ap:pqsadv "s:1 a:1"}

###################
#      CTCP       #
###################

#
## 10 ## CTCP/CTCR flood
#

lappend ap:udefs {ap:ctcps "2:30 180 kb 2"}

set ctcpf(kmsg) "CTCP flood detected. $kckcount(form)"

set ctcpf(wmsg) "Warning: You've triggered CTCP/CTCR flood protection, decrease your ctcps."

## Edit the following only if you choose a punish method above 5 (oper commands):

set ctcpf(ktype) 2

set ctcpf(klmsg) "CTCP/CTCR floods are not permissable on this network."

set ctcpf(ktime) 0

###################
#    TAKEOVER     #
###################

#
## 11 ## Mass deop.
#

lappend ap:udefs {ap:massd "5:1 30 kb 2"}

# Mass deop: deop abuser ? (0: no , 1: yes)
set massdeop(deop) 1

set massdeop(kmsg) "Mass deop detected. $kckcount(form)"

set massdeop(wmsg) "Warning: You've triggered the mass deop protection, do not repeat this action."

## Edit the following only if you choose a punish method above 5 (oper commands):

set massdeop(ktype) 2

set massdeop(klmsg) "Mass deops are not allowed on this network."

set massdeop(ktime) 0

#
## 12 ## Mass kick.
#

lappend ap:udefs {ap:massk "8:2 30 kb 2"}

# Mass kick: deop abuser ? (0: no , 1: yes)
set masskick(deop) 1

set masskick(kmsg) "Mass kick detected. $kckcount(form)"

set masskick(wmsg) "Warning: You've triggered mass kick protection, do not repeat this action."

## Edit the following only if you choose a punish method above 5 (oper commands):

set masskick(ktype) 2

set masskick(klmsg) "Mass kicks are prohibited on this network."

set masskick(ktime) 0

#
## 13 ## Mass ban (bans).
#

lappend ap:udefs {ap:massb "18:2 30 kb 2"}

# Mass ban (bans) deop abuser ? (1: yes , 0: no)
set massb(deop) 1

set massb(kmsg) "Mass ban is not allowed. $kckcount(form)"

set massb(wmsg) "Warning: You've triggered mass ban protection, do not repeat this action."

## Edit the following only if you choose a punish method above 5 (oper commands):

set massb(ktype) 2

set massb(klmsg) "Mass banning (bans) is prohibited on this network."

set massb(ktime) 0

#
## 14 ## Channel limit.
#

# Use .chanset #channel ap:limit <limit> (in DCC, 0 to disable)
# Note: this be the number that will be added to the channel's limit.
# Set default limit here:
lappend ap:udefs {ap:limit 8}

###################
#  MISCELLANEOUS  #
###################

#
## 15 ## Join flood.
#

lappend ap:udefs {ap:cjoin "3:2 120 kb 2"}

# Join flood: Check for join flood from same idents as well? (0: no, 1: yes)
set joinflood(checkident) 1

# Join flood: Lock channel when triggered ? (1: yes , 0: no)
set joinflood(lockchan) 1

# Join flood: If lock channel is enable, what modes ?
set joinflood(lockmode) "mR-k clone.join.flood"

# Join flood: lock time in seconds.
set joinflood(locktime) 45

set joinflood(kmsg) "Join flood detected. $kckcount(form)"

set joinflood(wmsg) "Warning: you've triggered join flood protection, further offence will cause harsher actions."

## Edit the following only if you choose a punish method above 5 (oper commands):

set joinflood(ktype) 2

set joinflood(klmsg) "Join floods are not permissable on this network."

set joinflood(ktime) 0

#
## 16 ## Part msg flood.
#

# Use .chanset #channel ap:partmsgs <message-length> <btime> <pmeth> <btype> (in DCC, 0 to disable)
# Set default value here:
lappend ap:udefs {ap:partmsgs "180 120 kb 2"}

# Also, you can ban if excess codes are used in a part msg:
# Use .chanset #channel ap:partmsgc r:<n> b:<n> u:<n> c:<n> <btime> <pmeth> <btype> (in DCC)
# Note: check codes protection to understand how codes checking work.
# r = reverse, b = bold, u = underline and c = colors.
# Set default rate here:
lappend ap:udefs {ap:partmsgc "r:35 b:35 u:35 c:35 30 kb 2"}

set pmsgf(kmsg) "Part msg flood detected. $kckcount(form)"

set pmsgf(wmsg) "Warning: You've triggered part msg flood protection, decrease text in your part reason."

## Edit the following only if you choose a punish method above 5 (oper commands):

set pmsgf(ktype) 2

set pmsgf(klmsg) "Part msg floods are not permissable on this network."

set pmsgf(ktime) 0

#
## 17 ## Revolving door.
#

# Use .chanset #channel ap:revdoor <seconds> <btime> <pmeth> <btype> (in DCC)
# example: setting this to 3 will make the bot ban whoever joins and parts/quits in 3 or less seconds.
# Set default value here:
lappend ap:udefs {ap:revdoor "3 120 kb 2"}

set revdoor(kmsg) "Join-part revolving door attempt detected. $kckcount(form)"

# Part messages that should not be considered as revdoor: (can use wildcards)
# Example: set revdoor(exempt) {"Registered."}
set revdoor(exempt) {}

set revdoor(wmsg) "Warning! you have triggered revolving-door protection, do not join-part channels."

## Edit the following only if you choose a punish method above 5 (oper commands):

set revdoor(ktype) 2

set revdoor(klmsg) "Revolving-door bots are not allowed on this network."

set revdoor(ktime) 0

#
## 18 ## Nick flood.
#

lappend ap:udefs {ap:nickf "4:12 60 w:k:kb 2"}

set nickflood(kmsg) "Nick flood detected. $kckcount(form)"

set nickflood(wmsg) "Warning: You've triggered nick flood protection, slow down your nick changes."

## Edit the following only if you choose a punish method above 5 (oper commands):

set nickflood(ktype) 2

set nickflood(klmsg) "Nick floods are not permissable on this network."

set nickflood(ktime) 0

#
## 19 ## Clones.
#

# Use .chanset #channel ap:clones <clones-number> <btime> <pmeth> <btype> (in DCC)
# Note: This will be the number of clones that triggers punishment.
# Set default value here:
lappend ap:udefs {ap:clones "8 120 kb 2"}

set eclones(kmsg) "Excess clones detected. $kckcount(form)"

set eclones(wmsg) "Warning: You've exceeded the maximum number of clones, remove your clones now."

# Do you want to check if the clones are still excess after warn?
# if yes then set this to the number of seconds to wait before checking again. (0 means no)
# NOTE: This should be less than <pwait> (at the beginning of the configuration).
set eclones(caw) 60

## Edit the following only if you choose a punish method above 5 (oper commands):

set eclones(ktype) 2

set eclones(klmsg) "Excess clones are not allowed on this network."

set eclones(ktime) 0

#
## 20 ## Bad nick.
#

# Use .chanset #channel ap:bnicks + <btime> <pmeth> <btype> (in DCC to enable)
# Set default value here: (+ enabled, - disabled)
lappend ap:udefs {ap:bnicks "+ 120 kb 2"}

set bnicks(global) {
    *porno*
    *horny*
    *horney*
    *fuck*
    *asshole*
    *dick*
    *bitch*
    *fagget*
    *shithead*
    *shitter*
    *penis*
    *pussy*
    *fukker*
}

set bnick(kmsg) "Bad nick detected. $kckcount(form)"

set bnick(wmsg) "Warning! you are using a bad nick, type /nick <nick> to change it."

set bnick(caw) 60

## Edit the following only if you choose a punish method above 5 (oper commands):

set bnick(ktype) 2

set bnick(klmsg) "Bad nicks are not allowed on this network."

set bnick(ktime) 0

#
## 21 ## Random drones.
#

# Use .chanset #channel ap:drones + <btime> <pmeth> <btype> (in DCC to enable)
# Set default value here: (+ enabled, - disabled)
# If you set <pmeth> to a positive-integer then the bot will only kick the drone once.
# So if the drone rejoins within this amount of seconds it won't be kicked again.
lappend ap:udefs {ap:drones "+ 180 45 2"}

# Random drones: What masks to exempt? (remember to change these or remoce them)
set droneexempts(global) { *example1*!*@* *!*example2*@* *!*@example3.net }

set drone(kmsg) "Possible random drone detected. $kckcount(form)"

set drone(wmsg) "Warning: You've triggered random drones protection, change your nick now."

## Edit the following only if you choose a punish method above 5 (oper commands):

set drone(ktype) 2

set drone(klmsg) "Random drones are not allowed on this network."

set drone(ktime) 0

#
## 22 ## Bad ident.
#

# Use .chanset #channel ap:bidents + <btime> <pmeth> <btype> (in DCC to enable)
# Set default value here: (+ enabled, - disabled)
lappend ap:udefs {ap:bidents "+ 120 kb 2"}

set bidents(global) {
    *porno*
    *horny*
    *horney*
    *fuck*
    *asshole*
    *dick*
    *bitch*
    *fagget*
    *shithead*
    *shitter*
    *penis*
    *pussy*
    *fukker*
}

set bident(kmsg) "Bad ident detected. $kckcount(form)"

set bident(wmsg) "Warning! you're using a bad ident. Disconnect, change it and then connect again."

set bident(caw) 60

## Edit the following only if you choose a punish method above 5 (oper commands):

set bident(ktype) 2

set bident(klmsg) "Bad idents are not allowed on this network."

set bident(ktime) 0

#
## 23 ## Bad chans/Excess chans.
#

# Use .chanset #channel ap:bchans + <btime> <pmeth> <btype> <scan-time> (in DCC to enable)
# <scan-time> is the time in minutes in which the bot will scan the channel for users in bad chans. (0 disable)
# Set default value here: (+ enabled, - disabled)
lappend ap:udefs {ap:bchans "- 90 kb 2 0"}

# For excess channels use:
# .chanset #channel ap:echans <excess-chan-number> <btime> <pmeth> <btype> <scan-time> (in DCC to enable)
# if <excess-chan-number> is 0, then it is disabled.
lappend ap:udefs {ap:echans "0 60 w:kb 2 0"}

# Set default global badchan list here:
set bchans(global) { #example1 #example2 #example3 }

# Bad chans flood protect, stop whois/ctcp incase of x joins in y seconds: (applies on bad versions too)
set bchan(floodprot) 4:10

# Bad chans kick message:
set bchan(kmsg) "Bad chan detected. $kckcount(form)"

# Excess chans kick message:
set bchan(ekmsg) "Excess chans detected. $kckcount(form)"

# Bad/Excess chans check after warning time in seconds.
# Incase you chose to warn the offender (punish method), this is the time in seconds to wait
# before checking again. (keep it 0 if you're not using warn)
# Setting this to 50 or less will be useless, also make sure this is less than pwait.
set bchan(caw) 60

# Bad chans warning message:
set bchan(wmsg) "Warning: You're on a bad chan %bchan, leave it or you'll be kicked from %chan. You have $bchan(caw) seconds to leave %bchan."

# Excess chans warning message:
set bchan(ewmsg) "Warning: You're on excess chans (%echan), maximum allowed is %max. You have $bchan(caw) seconds to leave excess chans."

## Edit the following only if you choose a punish method above 5 (oper commands):

set bchan(ktype) 2

set bchan(klmsg) "Joining bad channels is prohibited on this network."

set bchan(ktime) 0

#
## 24 ## Bad CTCP reply
#

# Use .chanset #channel ap:bctcrs + <btime> <pmeth> <btype> <scan-time> (in DCC to enable)
# Set default value here: (+ enabled, - disabled)
lappend ap:udefs {ap:bctcrs "- 120 kb 2 0"}

# Use .chanset #channel ap:ctcpchecks <ctcp-types>
# Set default CTCP replies to check for: (example: "VERSION TIME FINGER")
lappend ap:udefs {ap:ctcpchecks "VERSION"}

set bctcrs(global) {
    "*exploitation script*"
}

# %rtype is the CTCP reply type.
set bctcr(kmsg) "Bad %rtype reply detected. $kckcount(form)"

# Bad version check after warning time in seconds.
# Same as check for bad/excess chans.
set bctcr(caw) 60

set bctcr(wmsg) "Warning: You replied with \"%vers\" for %rtype request, if you don't change your script you'll be kicked from %chan. You have $bctcr(caw) seconds."

## Edit the following only if you choose a punish method above 5 (oper commands):

set bctcr(ktype) 2

set bctcr(klmsg) "Using bad scripts is prohibited on this network."

set bctcr(ktime) 0

#########################################
# BOTNET FLOOD PROTECTION (MASS FLOODS) #
#########################################

#
## 1 ## Botnet Text flood (lines).
#

# Use .chanset #channel ap:btextl <lines>:<seconds> <lockmode> <locktime> (in DCC, 0:0 to disable)
# Set default rate here:
lappend ap:udefs {ap:btextl "15:7 mR-k lines.flood 60"}

#
## 2 ## Botnet Text flood (chars).
#

lappend ap:udefs {ap:btextc "550:3 mR-k chars.flood 60"}

#
## 3 ## Botnet Notice flood (lines).
#

lappend ap:udefs {ap:bnotcl "4:2 mR-k lines.flood 60"}

#
## 4 ## Botnet Notice flood (chars).
#

lappend ap:udefs {ap:bnotcc "500:3 mR-k chars.flood 60"}

#
## 5 ## Botnet CTCP/CTCR flood.
#

lappend ap:udefs {ap:bctcp "4:60 mR-k ctcp.flood 60"}

#
## 6 ## Botnet join flood.
#

lappend ap:udefs {ap:massjoin "9:3 mR-k join.flood 60"}

#
## 7 ## Botnet revolving door flood.
#

## Note: ap:revdoor must be set for this to work.

lappend ap:udefs {ap:brevdoor "5:3 mR-k revdoor.flood 60"}

#
## 8 ## Botnet part msg flood.
#

## Note: ap:partmsgs or ap:partmsgc (or both) must be enabled for this to work.

lappend ap:udefs {ap:bpartmsg "5:3 mR-k partmsg.flood 60"}

#
## 9 ## Botnet Nick flood.
#

lappend ap:udefs {ap:bnickf "5:30 mR-k nick.flood 60"}

#
## 10 ## Botnet Codes flood.
#

lappend ap:udefs {ap:bcodes "25:3 mR-k codes.flood 60"}

###########################
#   PRIVATE PROTECTIONS   #
###########################

# Set here if you want the bot to set a restriction mode on itself when flooded.
# example: +R is used on DALnet so only registered users can send to the bot.
# set this to "" if you don't wish to change your bot's modes during a flood.
# NOTE: Maximum 1 mode, less or more means it's disabled.
set apfp(rmode) R

# Set here the time you want to keep the restriction mode in seconds.
set apfp(rtime) 30

# How many seconds do you want to stop answering data from server?
set apfp(itime) 45

#
## 1 ## Private text floods.
#

# Private text (lines) flood <lines>:<seconds>. (0:0 to disable)
set ptextl(punish) 12:6

# Private text (chars) flood <chars>:<seconds>. (0:0 to disable)
set ptextc(punish) 750:6

#
## 2 ## Private notice floods.
#

set pnotil(punish) 6:3

set pnotic(punish) 600:4

#
## 3 ## Private CTCP/CTCR flood.
#

set pctcpf(punish) 4:20

# Configurations end here. #
############################
#
######################################################################
# Code starts here, please do not edit anything unless you know TCL: #
# __________________________________________________________________ #
variable _VERSION "4.9b4"

proc istimer {arg {t timers}} {
    set a ""
    foreach rt [$t] {
        if {[string equal -nocase $arg [lindex $rt 1]]} {
            set a [lindex $rt 2] ; break
        }
    }
    set a
}

if {![info exists NumKicks]} {
    if {![file exists $kckcount(file)]} {set NumKicks 0} {
        set NumKicks [read -nonewline [set kcfop [open $kckcount(file)]]][close $kcfop][unset kcfop]
        if {![string is integer -strict $NumKicks]} {set NumKicks 0}
    }
}

variable bred 0
variable sfluds 0
foreach apudef ${ap:udefs} {
    if {[lindex $apudef 0] == "ap:level" && !$banthruX(do)} {continue}
    setudef str [lindex $apudef 0]
}
unset apudef

proc load {{b bind}} {
    if {$b == "loaded"} { set b bind }
    set nsc [namespace current]
    foreach joinb {cjoin massjoin bchans bctcrs drones bnicks bidents clones} {
        $b join - * "${nsc}::joins $joinb"
    }
    foreach pubmb {textl textc btextl btextc bcodes adv swear repeatl codes caps} {
        $b pubm - * "${nsc}::pubms $pubmb"
    }
    foreach notcb {notcl notcc bnotcl bnotcc bcodes adv swear codes} {
        $b notc - * "${nsc}::notc $notcb"
    }
    foreach ctcpb {textl textc btextl btextc bcodes adv swear repeatl codes caps} {
        $b ctcp - ACTION "${nsc}::ctcps $ctcpb"
    }
    foreach {modem modeb} {"* -b" rembs "* +b" massb "* -o" massd "* +o" cbcd} {
        $b mode - $modem "${nsc}::modes $modeb"
    }
    foreach partb {revdoor partmsgs adv swear} {
        $b part - * "${nsc}::parts $partb"
    }
    foreach signb {revdoor adv swear} {
        $b sign - * "${nsc}::parts $signb"
    }
    $b ctcp - * "${nsc}::ctcps ctcps"
    $b ctcp - * "${nsc}::ctcps bctcp"
    $b nick - * "${nsc}::joins bnicks"
    $b nick - * "${nsc}::nicks nickf"
    $b nick - * "${nsc}::nicks bnickf"
    $b ctcr - * ${nsc}::bctcrs
    $b ctcr - * ${nsc}::ctcr
    $b kick - * ${nsc}::massk
    $b raw - 319 ${nsc}::bchansgw
    $b msgm - * "${nsc}::ptext f"
    $b msgm - * "${nsc}::ptext adv"
    $b ctcp - ACTION "${nsc}::pctcp text"
    $b ctcp - * "${nsc}::pctcp ctcp"
    $b notc - * ${nsc}::pnotc
    $b ctcr - * ${nsc}::pctcr
    $b flud - * ${nsc}::pflud
    $b time - * ${nsc}::core
    $b time - * ${nsc}::antispamcore
    $b evnt - prerehash ${nsc}::unload
    $b evnt - prerestart ${nsc}::unload
    foreach apdccb {import reset disable add rem list monitor priv} {
        $b dcc n|n ap:$apdccb "${nsc}::cmd $apdccb"
    }
    if {$b == "bind"} {
        rd; variable logkbs; variable _VERSION
        foreach c [channels] { init $c }
        if {![info exists logkbs(logs)] && $logkbs(do)} {
            lappend logkbs(logs) "\$Log started [ctime [unixtime]]\$"
            if {[file exists $logkbs(file)]} {
                append logkbs(logs) " [lrange [split [read [set f [open $logkbs(file)]]] \n][close $f] 1 end]"
            }
        }
        checkscans
        if {[lsearch -glob [binds loaded] "* ${nsc}::load"] != -1} {
            unbind evnt - loaded ${nsc}::load
        }
        upvar #0 [ezilamn noisrev-pctc] cvar
        if {![string match "* [ezilamn "\002gnisoppO\002"] *" $cvar]} {
            set cvar "$cvar [ezilamn ")zF_riS aka( \002gnisoppO\002 yb [ezilamn $_VERSION]v noitcetor\002P\002ll\002A\002 gnisU -"]"
        }
        putlog "\002A\002ll\002P\002rotection v$_VERSION by Opposing Loaded..."
    }
}

proc joins {flood nick uhost hand chan {nn ""}} {
    if {$nn != ""} {set nick $nn}
    if {[isbotnick $nick]} {init $chan ; return 0}
    if {[set chan [string tolower $chan]] == "*" || [invalid:apc $nick $hand $chan]} {return 0}
    if {$flood != "bchans" && ![vcg $chan ap:$flood]} {return 0}
    foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
    switch -- $flood {
        "cjoin" {
            variable joinflood; variable apjoinfn
            foreach {j s} [cgsplit $off] {break}
            if {[invalid:apf $j $s]} {return 0}
            Nfollow $s apjoinfn([set h jnf:[string tolower [set f [lindex [split $uhost @] 1]]:$chan]]) $nick $uhost
            if {$joinflood(checkident)} {
                Nfollow $s apjoinfn([set hi jif:[string tolower [lindex [split $uhost @] 0]:$chan]]) $nick $uhost
            }
            if {[set ts [follow $s $h $j 1 1]] != -1 || ($joinflood(checkident) && [set ts2 [follow $s $hi $j 1 1]] != -1)} {
                if {[info exists ts2]} { set f [lindex [split $uhost @] 0]; set ts $ts2 ; set h $hi }
                if {$joinflood(lockchan)} {lockc $chan $joinflood(lockmode) $joinflood(locktime) "Join flood from $f"}
                punish $pmeth $apjoinfn($h) $chan [mapr $joinflood(kmsg) "$j joins in $ts secs"] $joinflood(wmsg) $btype $btime $joinflood(klmsg) $joinflood(ktime) $joinflood(ktype) [string tolower $f]:joinflood
            }
        }
        "massjoin" {
            foreach {o s} [cgsplit $off] {break}
            if {[invalid:apf $o $s] || [isbotnick $nick]} {return 0}
            checklc $s mjf:$chan $o $chan [join [lrange $cgot 1 end-1]] [lindex $cgot end] join
        }
        "bnicks" {
            variable bnick; variable bnicks
            if {$nn == ""} { set nn $nick }
            if {[string first # $chan] != 0 || [invalid:apc $nn $hand $chan]} {return 0}
            if {$off != "+"} {return 0}
            if {![info exists bnicks($chan)]} { set l $bnicks(global) } { set l $bnicks($chan) }
            set isbn 0
            foreach bn $l { if {[string match -nocase $bn $nn]} {set isbn 1; break} }
            if {$isbn} {
                if {$bnick(caw) > 0 && [string match -nocase *w* $pmeth]} {
                    set bnick([set ch $chan:[string tolower $uhost]]) 1
                    if {[istimer "[namespace current]::followrem bnick($ch)" utimers]==""} {
                        utimer [expr {$bnick(caw) + 1}] [list [namespace current]::followrem bnick($ch)]
                    }
                }
                punish $pmeth [list $nn $uhost] $chan [mapr $bnick(kmsg) $bn] $bnick(wmsg) $btype $btime $bnick(klmsg) $bnick(ktime) $bnick(ktype) [string tolower $uhost]:bnick
            }
        }
        "drones" {
            variable droneexempts
            if {$off != "+"} {return 0}
            set Nod 0
            if {[info exists droneexempts([set chan [string tolower $chan]])]} { set l $droneexempts($chan) } { set l $droneexempts(global) }
            foreach e $l { if {[string match -nocase $e $nick!$uhost]} {set Nod 1 ; break} }
            if {$Nod} {return 0}
            set id [string trimleft [lindex [split $uhost @] 0] ~]
            if {[follow 2 dr:$chan 3] != -1} {return 0}
            if {[regexp {^[a-z]{4,}![a-z]{4,}$} $nick!$id]} {
                if {(![string match {*[aeiou]*} $nick]) || ([regexp {^[^aeiou]{4}|[aeiou]{4}|q[^ua]|[^aeioux]x[^aeiouyx]|[^aeiouy]{5}} $nick dronm] && ![regexp {a{3}|e{3}|i{3}|o{3}|u{3}} $nick])} {
                    if {![info exists dronm]} { set dronm "no vowels" }
                    droneb $nick $uhost $chan $btime $pmeth $btype *$dronm*
                } elseif {![string match *$id* $nick] && [regexp {q[bcdfghknpqrstwzxv]|x[dfghkmnqrvz]|z[bcdfhmqrtvx]|v[bfghkmnqxw]|g[zv]|kz|bgb|wj|lx|jwm} $nick dronm]} {
                    droneb $nick $uhost $chan $btime $pmeth $btype *$dronm*
                }
            }
        }
        "bidents" {
            variable bident; variable bidents
            if {[invalid:apc $nick $hand $chan]} {return 0}
            if {$off != "+"} {return 0}
            scan $uhost {%[^@]} ident
            if {![info exists bidents($chan)]} { set l $bidents(global) } { set l $bidents($chan) }
            set isbi 0
            foreach bi $l { if {[string match -nocase $bi $ident]} {set isbi 1; break} }
            if {$isbi} {
                if {$bident(caw) > 0 && [string match -nocase *w* $pmeth]} {
                    set bident([set ch $chan:[string tolower $uhost]]) 1
                    if {[istimer "[namespace current]::followrem bident($ch)" utimers]==""} {
                        utimer [expr {$bident(caw) + 1}] [list [namespace current]::followrem bident($ch)]
                    }
                }
                punish $pmeth [list $nick $uhost] $chan [mapr $bident(kmsg) $bi] $bident(wmsg) $btype $btime $bident(klmsg) $bident(ktime) $bident(ktype) [string tolower $uhost]:bident
            }
        }
        "clones" {
            variable eclones
            if {![string is integer $off] || $off <= 0} {return 0}
            set c 0
            foreach ccheck [chanlist $chan] {
                if {[string equal -nocase [scan $uhost {%*[^@]@%s}] [scan [set chost [getchanhost $ccheck $chan]] {%*[^@]@%s}]]} {
                    incr c ; lappend cn $ccheck ; lappend cn $chost
                }
            }
            if {$c >= $off} {
                if {$eclones(caw) > 0 && [string match -nocase *w* $pmeth]} {
                    set eclones([set ch $chan:[string tolower [lindex [split $uhost @] 1]]]) 1
                    if {[istimer "[namespace current]::followrem eclones($ch)" utimers]==""} {
                        utimer [expr {$eclones(caw) + 1}] [list [namespace current]::followrem eclones($ch)]
                    }
                }
                punish $pmeth $cn $chan [mapr $eclones(kmsg) %ic/$c] $eclones(wmsg) $btype $btime $eclones(klmsg) $eclones(ktime) $eclones(ktype) [string tolower [scan $uhost {%*[^@]@%s}]]:eclones
            }
        }
        "bchans" {
            if {[vcg $chan ap:bchans] || [vcg $chan ap:echans]} {
                set off1 [lindex [split [channel get $chan ap:echans]] 0]
                if {![string is integer -strict $off1]} {set off1 0}
                if {$off == "+" || $off1 > 0} {
                    bchansw $nick $uhost $hand $chan 0
                }
            }
        }
        "bctcrs" {
            if {$off == "+"} { bchansw $nick $uhost $hand $chan 1 }
        }
    }
}

proc pubms {flood nick uhost hand chan arg} {
    if {[invalid:apc $nick $hand [set chan [string tolower $chan]]]} {return 0}
    if {![vcg $chan ap:$flood]} {return 0}
    foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
    switch -- $flood {
        "textl" - "textc" {
            foreach {o s} [cgsplit $off] {break}
            seqflood $flood $o $s $nick $uhost $chan $pmeth $btype $btime [string length $arg]
        }
        "btextl" - "btextc" {
            foreach {o s} [cgsplit $off] {break}
            if {[invalid:apf $o $s]} {return 0}
            checklc $s $flood:$chan $o $chan [join [lrange $cgot 1 end-1]] [lindex $cgot end] "text ([expr {$flood=="btextl"?"lines":"chars"}])" [expr {$flood=="btextl"?1:[string length $arg]}]
        }
        "repeatl" {
            variable repeatf
            foreach {o s} [cgsplit $off] {break}
            set arg [cf $arg]
            if {![invalid:apf $o $s]} {
                if {[set ts [follow $s rpt:[md5 [string tolower $uhost:$arg:$chan]] $o]] != -1} {
                    set kmsg [mapr $repeatf(kmsg) "$o repeats in $ts secs"]
                    set wmsg [string map {%type text} $repeatf(wmsg)] ; set reptype repeatl
                }
            }
            if {![info exists kmsg] && [vcg $chan ap:repeatc]} {
                set cgotc [split [channel get $chan ap:repeatc]]
                if {[string is integer [set i [lindex $cgotc 0]]] && $i > 0} {
                    set cl "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&"
                    for {set c 0} {$c < [string length $cl]} {incr c} {
                        if {[string match -nocase *[string repeat [string index $cl $c] $i]* $arg]} {
                            foreach {btime pmeth btype} [lrange $cgotc 1 end] {break}
                            set kmsg [mapr $repeatf(lkmsg) "${i}+ consecutive [string index $cl $c]'s"]
                            set wmsg [string map {%type letter} $repeatf(wmsg)] ; set reptype repeatc ; break
                        }
                    }
                }
            }
            if {[info exists kmsg]} {
                punish $pmeth [list $nick $uhost] $chan $kmsg $wmsg $btype $btime $repeatf(klmsg) $repeatf(ktime) $repeatf(ktype) [string tolower $uhost]:$reptype
            }
        }
        "codes" {
            variable codesf
            if {[string is integer [set cc [ccodes $chan $arg ap:codes]]] && $cc > 0} {
                punish [lindex $cgot 5] [list $nick $uhost] $chan [mapr $codesf(kmsg) "$cc chars affected"] $codesf(wmsg) [lindex $cgot 6] [lindex $cgot 4] $codesf(klmsg) $codesf(ktime) $codesf(ktype) [string tolower $uhost]:codesf
            }
        }
        "bcodes" {
            foreach {o s} [cgsplit $off] {break}
            if {[invalid:apf $o $s]} {return 0}
            checklc $s bcodes:$chan $o $chan [join [lrange $cgot 1 end-1]] [lindex $cgot end] "control codes" [regexp -all {\002|\003\d{1,2}(,\d{1,2})?|\017|\026|\037} $arg]
        }
        "adv" {
            if {$off != "+"} {return 0}
            variable adv
            if {[set advword [isspam $arg $chan]] != ""} {
                punish $pmeth [list $nick $uhost] $chan [mapr $adv(kmsg) *$advword*] $adv(wmsg) $btype $btime $adv(klmsg) $adv(ktime) $adv(ktype) [string tolower $uhost]:adv
            }
        }
        "swear" {
            variable swear ; variable bwords
            if {$off != "+"} {return 0}
            set arg [cf $arg]
            if {![info exists bwords($chan)]} { set l $bwords(global) } { set l $bwords($chan) }
            foreach bw $l {
                if {[string match -nocase $bw $arg]} {
                    punish $pmeth [list $nick $uhost] $chan [mapr $swear(kmsg) $bw] $swear(wmsg) $btype $btime $swear(klmsg) $swear(ktime) $swear(ktype) [string tolower $uhost]:swear
                    break
                }
            }
        }
        "caps" {
            variable capsp
            set linelen [string length [set arg [cf $arg]]]
            foreach {p l} [cgsplit $off] {break}
            if {[invalid:apf $p $l] || $linelen < $l} {return 0}
            if {[set caps [regexp -all {[A-Z]} $arg]] > 0} {
                if {[set pl [expr {$caps * 100 / $linelen}]] >= $p} {
                    punish $pmeth [list $nick $uhost] $chan [mapr $capsp(kmsg) "${pl}% of $linelen chars"] $capsp(wmsg) $btype $btime $capsp(klmsg) $capsp(ktime) $capsp(ktype) [string tolower $uhost]:capsp
                }
            }
        }
    }
}

proc notc {flood nick uhost hand arg chan} {
    if {[isbotnick [lindex [split $chan @] 0]] || [string first @ $chan] == 0 || ![regexp {.+!.+@.+} $nick!$uhost]} {return 0}
    if {![vcg $chan ap:$flood]} {return 0}
    if {[invalid:apc $nick $hand [set chan [string tolower $chan]]]} {return 0}
    foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
    switch -- $flood {
        "notcl" - "notcc" {
            foreach {o s} [cgsplit $off] {break}
            seqflood $flood $o $s $nick $uhost $chan $pmeth $btype $btime [string length $arg]
        }
        "codes" - "bcodes" - "adv" - "swear" {
            pubms $flood $nick $uhost $hand $chan $arg
        }
        "bnotcl" - "bnotcc" {
            foreach {o s} [cgsplit $off] {break}
            if {[invalid:apf $o $s]} {return 0}
            checklc $s $flood:$chan $o $chan [join [lrange $cgot 1 end-1]] [lindex $cgot end] "notice ([expr {$flood=="bnotcl"?"lines":"chars"}])" [expr {$flood=="bnotcl"?1:[string length $arg]}]
        }
    }
}

proc ctcps {flood nick uhost hand chan kw arg} {
    if {[isbotnick [lindex [split $chan @] 0]] || [string equal -nocase chat $kw]} {return 0}
    if {[string equal -nocase action $kw]} {
        pubms $flood $nick $uhost $hand $chan $arg
    } {
        if {![vcg $chan ap:$flood]} {return 0}
        if {[invalid:apc $nick $hand [set chan [string tolower $chan]]]} {return 0}
        foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
        switch -- $flood {
            "ctcps" {
                foreach {o s} [cgsplit $off] {break}
                if {[invalid:apf $o $s]} {return 0}
                checkf $s $o ctcpc:[string tolower $uhost:$chan] $uhost $chan $pmeth $nick {$o CTCPs} $btype $btime ctcpf
            }
            "bctcp" {
                foreach {o s} [cgsplit $off] {break}
                if {[invalid:apf $o $s]} {return 0}
                checklc $s bctcpc:$chan $o $chan [join [lrange $cgot 1 end-1]] [lindex $cgot end] CTCP
            }
        }
    }
}

proc modes {flood nick uhost hand chan mc targ} {
    if {$flood == "cbcd" && [isbotnick $targ] && [follow 5 botoped:$chan 2 1 1] == -1} {
        checkbcd $chan
    } elseif {$flood == "rembs"} {
        if {[set t [istimer "pushmode $chan -b $targ"]]!=""} { killtimer $t }
    } elseif {$flood != "cbcd"} {
        if {[isbotnick $nick] && $flood == "massb"} {
            variable logkbs
            if {$logkbs(do)} { aplog "\[[clock format [clock seconds] -format %T]\] Banned $targ on $chan" }
        }
        if {![vcg $chan ap:$flood] || [isbotnick $nick] || [matchattr $hand fmo|fmo $chan]} {return 0}
        foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
        variable serv
        switch -- $flood {
            "massb" {
                variable massb
                foreach {o s} [cgsplit $off] {break}
                if {$nick == "" || $nick == $targ || [invalid:apf $o $s]} {return 0}
                if {[set ts [follow $s mssb:[string tolower $uhost:$chan] $o]] != -1} {
                    if {$massb(deop)} {
                        putquick "$serv(nick) :[string map [list %nick $nick %chan $chan] $serv(command)]"
                        if {[botisop $chan]} { putquick "MODE $chan -o $nick" }
                    }
                    punish $pmeth [list $nick $uhost] $chan [mapr $massb(kmsg) "$o bans in $ts secs"] $massb(wmsg) $btype $btime $massb(klmsg) $massb(ktime) $massb(ktype) [string tolower $uhost]:massb
                }
            }
            "massd" {
                variable massdeop
                foreach {o s} [cgsplit $off] {break}
                if {$nick == "" || $nick == $targ || [invalid:apf $o $s]} {return 0}
                if {[set ts [follow $s mssd:[string tolower $uhost:$chan] $o]] != -1} {
                    if {$massdeop(deop)} {
                        putquick "$serv(nick) :[string map [list %chan $chan %nick $nick] $serv(command)]"
                        if {[botisop $chan]} { putquick "MODE $chan -o $nick" }
                    }
                    punish $pmeth [list $nick $uhost] $chan [mapr $massdeop(kmsg) "$o deops in $ts secs"] $massdeop(wmsg) $btype $btime $massdeop(klmsg) $massdeop(ktime) $massdeop(ktype) [string tolower $uhost]:massdeop
                }
            }
        }
    }
}

proc parts {flood nick uhost hand chan arg} {
    if {[invalid:apc $nick $hand [set chan [string tolower $chan]]]} {return 0}
    if {![vcg $chan ap:$flood]} {return 0}
    foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
    switch -- $flood {
        "revdoor" {
            variable revdoor ; variable banthruX ; variable ::max-bans
            if {![string is integer $off] || $off <= 0} {return 0}
            if {[set gcj [getchanjoin $nick $chan]] >= [set ut [unixtime]]-$off} {
                if {[vcg $chan ap:brevdoor]} {
                    foreach {o s} [cgsplit [lindex [set cgot2 [split [channel get $chan ap:brevdoor]]] 0]] {break}
                    if {![invalid:apf $o $s]} {
                        checklc $s brevdc:$chan $o $chan [join [lrange $cgot2 1 end-1]] [lindex $cgot2 end] "revolving door"
                    }
                }
                set rvne 0
                foreach rve $revdoor(exempt) { if {[string match -nocase $rve $arg]} {set rvne 1 ; break} }
                if {$rvne} {return 0}
                punish $pmeth [list $nick $uhost] $chan [mapr $revdoor(kmsg) "[expr {$ut-$gcj}] sec(s) revolution"] $revdoor(wmsg) $btype $btime $revdoor(klmsg) $revdoor(ktime) $revdoor(ktype) [string tolower $uhost]:revdoor
            }
        }
        "partmsgs" {
            variable pmsgf
            if {($off > 0 && [set al [string length $arg]] >= $off) || [set cl [ccodes $chan $arg ap:partmsgc]] > 0} {
                if {[vcg $chan ap:bpartmsg]} {
                    foreach {o s} [cgsplit [lindex [set cgot2 [split [channel get $chan ap:bpartmsg]]] 0]] {break}
                    if {![invalid:apf $o $s]} {
                        checklc $s bpmsgc:$chan $o $chan [join [lrange $cgot2 1 end-1]] [lindex $cgot2 end] "part msg"
                    }
                }
                if {[info exists cl]} {
                    set kmsg [mapr $pmsgf(kmsg) "$cl chars affected by codes"]
                    foreach {fo1 fo2 fo3 fo4 btime pmeth btype} [split [channel get $chan ap:partmsgc]] {break}
                } {
                    set kmsg [mapr $pmsgf(kmsg) "$al chars"]
                }
                punish $pmeth [list $nick $uhost] $chan $kmsg $pmsgf(wmsg) $btype $btime $pmsgf(klmsg) $pmsgf(ktime) $pmsgf(ktype) [string tolower $uhost]:pmsgf
            }
        }
        "adv" - "swear" {
            if {![vcg $chan ap:pqsadv]} {return 0}
            foreach {s a} [split [channel get $chan ap:pqsadv]] {
                set s [lindex [split $s :] 1]
                set a [lindex [split $a :] 1]
                break
            }
            if {($flood == "adv" && $a) || ($flood == "swear" && $s)} {
                pubms $flood $nick $uhost $hand $chan $arg
            }
        }
    }
}

proc nicks {flood nick uhost hand chan nn} {
    if {[string first # $chan] != 0 || [invalid:apc $nn $hand [set chan [string tolower $chan]]]} {return 0}
    if {![vcg $chan ap:$flood]} {return 0}
    foreach {off btime pmeth btype} [set cgot [split [channel get $chan ap:$flood]]] {break}
    foreach {o s} [cgsplit $off] {break}
    if {[invalid:apf $o $s]} {return 0}
    switch -- $flood {
        "nickf" {
            checkf $s $o nckflood:[string tolower $uhost:$chan] $uhost $chan $pmeth $nn {$o changes} $btype $btime nickflood
        }
        "bnickf" {
            checklc $s bnickc:$chan $o $chan [join [lrange $cgot 1 end-1]] [lindex $cgot end] nick
        }
    }
}

proc massk {nick uhost hand chan targ arg} {
    variable masskick ; variable serv
    if {![isbotnick $nick]} {
        if {![vcg $chan ap:massk]} {return 0}
        foreach {off btime pmeth btype} [split [channel get $chan ap:massk]] {break}
        foreach {o s} [cgsplit $off] {break}
        if {$nick == $targ || [invalid:apf $o $s] || [matchattr $hand fmo|fmo $chan]} {return 0}
        if {[set ts [follow $s mssk:[string tolower $uhost:$chan] $o]] != -1} {
            if {$masskick(deop)} {
                putquick "$serv(nick) :[string map [list %chan $chan %nick $nick] $serv(command)]"
                if {[botisop $chan]} { putquick "MODE $chan -o $nick" }
            }
            punish $pmeth [list $nick $uhost] $chan [mapr $masskick(kmsg) "$o kicks in $ts secs"] $masskick(wmsg) $btype $btime $masskick(klmsg) $masskick(ktime) $masskick(ktype) [string tolower $uhost]:masskick
        }
    } {
        variable logkbs
        if {$logkbs(do)} { aplog "\[[clock format [clock seconds] -format %T]\] Kicked $targ from $chan for reason: $arg" }
    }
}

proc lim {} {
    foreach c [channels] {
        if {![vcg $c ap:limit]} {continue}
        if {[set l [channel get $c ap:limit]] > 0 && [botisop $c]} {
            if {[string match *l* [lindex [split [getchanmode $c]] 0]]} {
                if {abs($l - ([set cl [lindex [split [getchanmode $c]] end]] - [set ccl [llength [chanlist $c]]])) >= ceil($l * 30 / 100.0)} {
                    pushmode $c +l [expr {$ccl + $l}]
                }
            } {pushmode $c +l [expr {[llength [chanlist $c]] + $l}]}
        }
    }
}

proc ctcr {nick uhost hand chan kw arg} {
    if {[isbotnick [lindex [split $chan "@"] 0]] || [lindex [split $chan "@"] 1] != ""} {return 0}
    ctcps bctcp $nick $uhost $hand $chan $kw $arg
    ctcps ctcp $nick $uhost $hand $chan $kw $arg
}

proc ccodes {ch a f} {
    if {![vcg $ch $f]} {return 0}
    foreach {r b u c btime pmeth btype} [split [channel get $ch $f]] {break}
    if {![icodes [set codes "$r $b $u $c"]]} {return 0}
    set p 0
    foreach cg [split $codes] {
        scan $cg {%[^:]:%s} t v
        if {$v <= 0} {continue}
        set t [string map {r \026 b \002 u \037 c \003} $t]
        if {![info exists fc($t)]} {set fc($t) 0}
        foreach l [lrange [split $a $t] 1 end] {
            set l [string range [set l [cf $l]] 0 [expr {[set fo [string first \017 $l]] == -1?"end":"$fo"}]]
            if {$t == "\003"} {
                if {[regsub {^\d{1,2}(,\d{1,2})?} $l "" l]} {
                    if {[incr fc($t) [string length $l]] >= $v} {set p 1; break}
                    continue
                }
            }
            if {![info exists cc($t)]} {set cc($t) 0}
            if {!($cc($t) % 2)} { if {[incr fc($t) [string length $l]] >= $v} {set p 1; break} }
            incr cc($t)
        }
        if {$p} {break}
    }
    if {$p} {return $fc($t)}
    return 0
}

proc isspam {arg {chan ""}} {
    variable adexempts; variable adwords
    set arg [string tolower [cf $arg]]; set advword ""
    if {$chan != "" && [info exists adexempts($chan)]} {set l $adexempts($chan)} {set l $adexempts(global)}
    foreach ade $l {set arg [string map [list [string map [list %chan $chan] $ade] ""] $arg]}
    if {![regexp {(^|\s)((www\.|#)[^\s]|ftp://|http://|(/server|//(\.?)write)\s)} $arg advword]} {
        if {$chan != "" && [info exists adwords($chan)]} {set l $adwords($chan)} {set l $adwords(global)}
        set isad 0
        foreach advword $l { if {[string match -nocase $advword $arg]} {set isad 1; break} }
        if {!$isad} {set advword ""}
    }
    return $advword
}

proc bchansw {nick uhost hand chan type} {
    variable bchan; variable apbcnick; variable apbvnick
    foreach {o s} [split $bchan(floodprot) :] {break}
    if {!$type && [follow $s bchw:[set chan [string tolower $chan]] $o] == -1 && ([vcg $chan ap:bchans] || [vcg $chan ap:echans])} {
        set apbcnick([string tolower $nick]) $chan
        putserv "whois $nick"
    } elseif {$type && [follow $s ctcrr:$chan $o] == -1 && [vcg $chan ap:bctcrs]} {
        foreach bctcr [split [channel get $chan ap:ctcpchecks]] {
            if {[set bctcr [string toupper $bctcr]] != ""} {
                set apbvnick([string tolower $nick]:$bctcr) $chan
                putserv "privmsg $nick :\001$bctcr\001"
            }
        }
    }
}

proc bchansgw {from key arg} {
    variable bchan ; variable bchans ; variable apbcnick
    set arg [string trim $arg]
    if {![info exists apbcnick([set nick [string tolower [lindex [split $arg] 1]]])]} {return 0}
    set chan $apbcnick($nick)
    if {[vcg $chan ap:bchans]} {
        foreach {off btime pmeth btype} [split [channel get $chan ap:bchans]] {break}
    }
    if {[info exists off] && $off == "+"} {
        if {![info exists bchans($chan)]} { set l $bchans(global) } { set l $bchans($chan) }
        foreach c [split [string tolower [join [lrange [split $arg] 2 end]]]] {
            set c [string trimleft $c ":@%+"]
            foreach bc $l {
                if {[string match $bc $c]} {
                    set uhost [getchanhost $nick $chan]
                    if {$uhost != ""} {
                        set kmsg [mapr $bchan(kmsg) $c]
                        set wmsg [string map [list %chan $chan %bchan $c] $bchan(wmsg)]
                        putlog "\002AP\002: Bchans: Detected \002$nick\002 on (\002$c\002) joining \002$chan\002."
                    }
                    break
                }
            }
            if {[info exists uhost]} {break}
        }
    }
    if {![info exists kmsg] && [vcg $chan ap:echans]} {
        foreach {off btime pmeth btype} [split [channel get $chan ap:echans]] {break}
        if {$off > 0 && [set ecs [llength [lrange [split $arg] 2 end]]] >= $off} {
            set uhost [getchanhost $nick $chan]
            if {$uhost != ""} {
                set kmsg [mapr $bchan(ekmsg) "$ecs chans"]
                set wmsg [string map [list %echan "$ecs chans" %max [expr {$off-1}]] $bchan(ewmsg)]
                putlog "\002AP\002: Echans: Detected \002$nick\002 on \002$ecs\002 channels."
            }
        }
    }
    if {[info exists kmsg]} {
        if {$bchan(caw) > 0 && [string match -nocase *w* $pmeth]} {
            set bchan([set ch $chan:[string tolower $uhost]]) 1
            if {[istimer "[namespace current]::followrem bchan($ch)" utimers]==""} {
                utimer [expr {$bchan(caw) + 1}] [list [namespace current]::followrem bchan($ch)]
            }
        }
        foreach aChan [channels] {
            if {[onchan $nick $aChan]} {
                if {![string equal -nocase $aChan $chan]} {
                    if {[string is integer -strict $off] && [vcg $aChan ap:echans]} {
                        foreach {off btime pmeth btype} [split [channel get $aChan ap:echans]] {break}
                    } elseif {[vcg $aChan ap:bchans]} {
                        foreach {off btime pmeth btype} [split [channel get $aChan ap:bchans]] {break}
                    } {
                        continue
                    }
                }
                punish $pmeth [list $nick $uhost] $aChan $kmsg $wmsg $btype $btime $bchan(klmsg) $bchan(ktime) $bchan(ktype) [string tolower $uhost]:badchan
            }
        }
    }
    return 0
}

proc bctcrs {nick uhost hand targ kw arg} {
    variable bctcr; variable bctcrs; variable apbvnick
    if {![isbotnick $targ] || ![info exists apbvnick([set nkw [string tolower $nick]:[set kw [string toupper $kw]]])]} {return 0}
    set chan $apbvnick($nkw); unset apbvnick($nkw)
    if {![vcg $chan ap:bctcrs]} {return 0}
    foreach {off btime pmeth btype} [split [channel get $chan ap:bctcrs]] {break}
    if {![info exists bctcrs($chan)]} { set l $bctcrs(global) } { set l $bctcrs($chan) }
    set m 0
    foreach bv $l { if {[string match -nocase $bv $arg]} {set m 1; break} }
    if {$m} {
        if {$bctcr(caw) > 0 && [string match -nocase *w* $pmeth]} {
            set bctcr([set ch $chan:[string tolower $uhost]]) 1
            if {[istimer "[namespace current]::followrem bctcr($ch)" utimers]==""} {
                utimer [expr {$bctcr(caw) + 1}] [list [namespace current]::followrem bctcr($ch)]
            }
        }
        punish $pmeth [list $nick $uhost] $chan [string map [list %rtype $kw] [mapr $bctcr(kmsg) $bv]] [string map [list %rtype $kw] [mapr $bctcr(wmsg) $bv]] $btype $btime $bctcr(klmsg) $bctcr(ktime) $bctcr(ktype) [string tolower $uhost]:bctcrs
    }
}

proc checkbcd c {
    variable cbcd
    if {!$cbcd(check) || [nap:chan $c $cbcd(chans)]} {return 0}
    foreach n [chanlist $c] {
        foreach sc $cbcd(procs) {
            joins [string map {echans bchans} $sc] $n [getchanhost $n $c] [nick2hand $n $c] $c
        }
    }
}

proc core {m h args} {
    lim; checkscans
    variable NumKicks; variable kckcount; variable ptrig; variable pwait; variable logkbs
    variable removebs; variable ::max-bans
    if {[regexp {03:00} $h:$m] && [info exists logkbs(logs)]} {
        if {$logkbs(do) == 1} {
            set f [open $logkbs(file).yesterday w]
        } elseif {$logkbs(do) == 2} {
            set f [open $logkbs(file).[clock format [expr {[unixtime]-86400}] -format "%d.%m.%y"] w]
        }
        if {[info exists logkbs(logs)]} { foreach log $logkbs(logs) { if {$log != ""} { puts $f $log } } }
        close $f
        set logkbs(logs) [list "\$Log started [ctime [unixtime]]\$"]
    }
    if {$removebs} {
        foreach c [channels] {
            if {[botisop $c] && [llength [set cl [chanbans $c]]] >= ${max-bans}} {
                foreach b [lrange $cl 0 [expr {$removebs-1}]] { pushmode $c -b [lindex $b 0] }
            }
        }
    }
    if {[scan $m %d]%2} {return 0}
    foreach {pn pe} [array get ptrig] { if {[unixtime]-[lindex $pe 1] > $pwait} {unset ptrig($pn)} }
    if {[regexp {\d0} $m]} {
        set kc [open $kckcount(file) w]
        puts $kc $NumKicks ; close $kc
        variable following
        foreach {an ae} [array get following] {
            if {([clock clicks -milliseconds]-[lindex $ae 1])/1000 > $pwait} {
                unset following($an)
            }
        }
        variable punishing
        foreach {i s} [array get punishing] {if {[clock clicks -milliseconds] >= $s} {unset punishing($i)}}
        if {$logkbs(do)} {
            set f [open $logkbs(file) w]
            foreach log $logkbs(logs) { if {$log != ""} { puts $f $log } }
            close $f
        }
    }
}

set antispam(next) -1
set antispam(tvhost4) $_vhost4
set antispam(tvhost6) $_vhost6
set antispam(thostname) $_hostname

if {${::numversion} >= $_EGGDROP_1_8} {
    # Eggdrop >= 1.8
    proc set_vhosts {} {
        variable antispam
        if {[info exists antispam(vhost4)]} {
            set ::vhost4 $antispam(vhost4)
        }
        if {[info exists antispam(vhost6)]} {
            set ::vhost6 $antispam(vhost6)
        }
    }
    proc reset_vhosts {} {
        variable antispam
        if {$::vhost4 != $antispam(tvhost4)} {
            set ::vhost4 $antispam(tvhost4)
        }
        if {$::vhost6 != $antispam(tvhost6)} {
            set ::vhost4 $antispam(tvhost4)
        }
    }
} {
    # Eggdrop < 1.8
    proc set_vhosts {} {
        variable antispam
        if {[info exists antispam(vhost4)]} {
            set {::my-ip} $antispam(vhost4)
        }
        if {[info exists antispam(hostname)]} {
            set {::my-hostname} $antispam(hostname)
        }
    }
    proc reset_vhosts {} {
        variable antispam
        if {${::my-ip} != $antispam(tvhost4)} {
            set {::my-ip} $antispam(tvhost4)
        }
        if {${::my-hostname} != $antispam(thostname)} {
            set {::my-hostname} $antispam(thostname)
        }
    }
}


proc antispamcore {m h args} {
    variable antispam; variable Sec
    if {![info exists antispam(idx)] || ![valididx $antispam(idx)]} {
        if {[info exists antispam(idx)]} {unset antispam(idx)}
        if {[info exists antispam(cnick)]} {unset antispam(cnick)}
        foreach {s p} [split [lindex [lindex $::servers [expr {[incr antispam(next)]%[llength $::servers]}]] 0] :] {break}
        foreach c [channels] {
            if {[vcg $c ap:antispam] && [lindex [split [channel get $c ap:antispam]] 0] == "+"} {
                set_vhosts
                control [connect $s $p] [namespace current]::antispambot
                putlog "\002AP\002: AntiSpamBot: Connecting to $s:$p..."
                break
            }
        }
        return
    }
    set asbc 0
    foreach c [channels] {
        set mins [expr {[scan $m %d]+([scan $h %d]*60)}]
        foreach {off greet cycle idle} [split [channel get $c ap:antispam]] {break}
        if {$off == "+"} {incr asbc}
        if {[onchan $antispam(cnick) $c] && $off != "+"} {
            putdcc $antispam(idx) "part $c"
        } elseif {$cycle != 0 && $mins%$cycle == 0 && [onchan $antispam(cnick) $c]} {
            if {![info exists antispam([set e [string tolower $c]:idle])]} {set antispam($e) [unixtime]}
            if {[unixtime]-$antispam($e) < $idle*60 && [botisop $c]} {
                putlog "\002AP\002: AntiSpamBot: Cycling $c..."
                putdcc $antispam(idx) "part $c"
                putdcc $antispam(idx) "join $c"
            }
        } {if {![onchan $antispam(cnick) $c] && $off == "+"} {putdcc $antispam(idx) "join $c"}}
    }
    if {!$asbc} {
        putdcc $antispam(idx) quit
        putlog "\002AP\002: AntiSpamBot: Disconnected (disabled on all channels)..."
    }
}

proc antispambot {idx arg} {
    variable antispam; variable adv; variable greetexempts; variable antiSpamOnline
    reset_vhosts
    if {$arg == ""} {
        if {[info exists antispam(idx)]} {unset antispam(idx)}
        if {[info exists antispam(cnick)]} {unset antispam(cnick)}
        if {[info exists antiSmapOnline]} {unset antiSpamOnline}
        if {[info exists antispam(qrsn)]} {set rsn $antispam(qrsn); unset antispam(qrsn)} {set rsn (dead)}
        putlog "\002AP\002: AntiSpamBot: Disconnected $rsn..."
        return
    }
    if {![info exists antispam(idx)] && ![info exists antispam(cnick)]} {
        set antispam(idx) $idx ; set antispam(cnick) $antispam(nick)
        putdcc $idx "user $antispam(user) 8 * :$antispam(realname)"
        putdcc $idx "nick $antispam(cnick)"
        return
    }
    if {![info exists antiSpamOnline]} {
        set antiSpamOnline 1
        if {[istimer [namespace current]::dumpqueues utimers]==""} {
            variable Sec -1
            utimer 1 [namespace current]::dumpqueues
        }
    }
    switch -- [string tolower [lindex [split $arg] 0]] {
        "ping" {putdcc $idx "pong [lindex [split $arg] 1]"}
        "error" {set antispam(qrsn) [join [lrange [split $arg] 4 end]]; return}
    }
    switch -- [set raw [string tolower [lindex [split $arg] 1]]] {
        "privmsg" - "notice" {
            set src [lindex [split $arg] 0]
            set asbn [lindex [split $arg] 2]
            if {![string equal -nocase $asbn $antispam(cnick)]} {return}
            if {[scan $src {:%[^!]!%s} nick uhost] != 2} {return}
            set text [join [lrange [split $arg] 3 end]]
            if {[set advword [isspam $text]] == ""} {
                if {$raw == "privmsg" && [string match ":\001DCC Send *\001" $text]} {set advword "DCC SEND"}
            }
            if {$advword == ""} {
                foreach {o s} [split $antispam(mprot) :] {break}
                if {[follow $s asbm $o 1 1] != -1} {return}
                set ism 0
                foreach t $antispam(t) {if {[string match -nocase $t $text]} {set ism 1; break}}
                set l $greetexempts(global)
                set f 0; foreach ge $l { if {[string match -nocase $ge $nick!$uhost]} {set f 1;break} }
                if {$ism && !$f} {asb:queue $nick [lindex $antispam(r) [rand [llength $antispam(r)]]]}
            }
        }
        "invite" {
            set src [lindex [split $arg] 0]
            if {[scan $src {:%[^!]!%s} nick uhost] != 2} {return}
            set advword "INVITE"
        }
        "001" {
            putlog "\002AP\002: AntiSpamBot: Connected and registered as $antispam(cnick)."
            set antispam(pong) 1; set antispam(idx) $idx
            foreach c [channels] {
                if {![vcg $c ap:antispam]} {continue}
                if {[lindex [split [channel get $c ap:antispam]] 0] == "+"} {
                    putdcc $idx "join $c"
                }
            }
        }
        "433" {
            if {$antispam(cnick) == $antispam(nick)} {set antispam(cnick) $antispam(altnick)} {
                set antispam(cnick) [string replace $antispam(nick) end end [rand 10]]
            }
            putdcc $idx "nick $antispam(cnick)"
        }
        "nick" {
            if {[string trimleft [lindex [split [lindex [split $arg] 0] @] 0] :] == $antispam(cnick)} {
                set antispam(cnick) [string trimleft [lindex [split $arg] 2] :]
            }
        }
        "join" {
            foreach {o s} [split $antispam(jprot) :] {break}
            set c [string trim [string tolower [string trimleft [lindex [split $arg] end] :]]]
            if {![validchan $c]} {return}
            foreach {off greet cy i} [split [channel get $c ap:antispam]] {break}
            if {[vcg $c ap:antispam] && $off == "+"} {
                if {[scan [lindex [split $arg] 0] {:%[^!]!%s} nick uhost] != 2} {return}
                if {[string equal -nocase $nick $antispam(cnick)] || [follow $s asbj:$c $o 1 1] != -1} {return}
                set antispam($c:idle) [unixtime]
                if {[info exists greetexempts($c)]} {set l $greetexempts($c)} {set l $greetexempts(global)}
                set f 0; foreach ge $l { if {[string match -nocase $ge $nick!$uhost]} {set f 1;break} }
                if {!$f && $greet == "+" && ![invalid:apc $nick [finduser $nick!$uhost] $c]} {
                    asb:queue $nick [string map [list %nick $nick] $antispam(greet)]
                }
            }
        }
    }
    if {[info exists advword] && $advword != ""} {
        set hand [finduser [string trimleft $src :]]
        foreach c [channels] {
            if {![vcg $c ap:antispam] || ![vcg $c ap:adv] || [invalid:apc $nick $hand $c]} {continue}
            if {[lindex [split [channel get $c ap:antispam]] 0] == "+"} {
                foreach {off btime pmeth btype} [split [channel get $c ap:adv]] {break}
                if {$off == "+"} {
                    if {$antispam(banall) || [onchan $nick $c]} {
                        punish $pmeth [list $nick $uhost] $c [mapr $adv(kmsg) *$advword*] $adv(wmsg) $btype $btime $adv(klmsg) $adv(ktime) $adv(ktype) [string tolower $uhost]:adv
                    }
                }
            }
        }
    }
}

proc cmd {cmd hand idx arg} {
    variable banthruX
    set arg [string tolower $arg]
    if {[regexp {add|rem|list} $cmd]} {
        set lists {bchans bnicks bidents bwords adexempts droneexempts bctcrs adwords greetexempts}
        if {[regexp {add|rem} $cmd]} {
            set synp " <bad chans/nicks/idents/bwords/adexempts/droneexempts/bctcrs/adwords/greetexempts>"
            set sl [join [lrange [split $arg] 2 end]]
            if {[join [set l [cl $sl]]]==""} {
                putdcc $idx "\002AP\002: SYNTAX: .ap:$cmd <[join $lists /]> <#chan/global>$synp."
                return 0
            }
        } {set synp ""}
        if {[scan $arg "%s %s" t c] != 2} {
            putdcc $idx "\002AP\002: SYNTAX: .ap:$cmd <[join $lists /]> <#chan/global>$synp."
            return 0
        }
        if {[lsearch -exact $lists $t] == -1} {
            putdcc $idx "\002AP\002: Invalid list \002$t\002, should be one of: [join $lists ", "]."
            return 0
        }
        if {[set ti [string first # $c]] != 0 && $c != "global"} {
            putdcc $idx "\002AP\002: Invalid chan \002$c\002, either use a valid chan or 'global'."
            return 0
        }
        upvar [namespace current]::$t aptv
    } elseif {[regexp {reset|disable} $cmd]} {
        if {[set chans [string map [list * [channels]] [lindex [split $arg] 0]]] == ""} {
            putdcc $idx "\002AP\002: SYNTAX: .ap:$cmd <#channel>"
            return 0
        }
        variable ap:udefs
    }
    switch -- $cmd {
        "add" {
            if {$ti == 0} {
                if {[validchan $c]} {
                    if {![info exists aptv($c)]} {
                        set aptv($c) $l
                        set unfound $l
                    } {
                        foreach bs $l {
                            if {[lsearch -exact $aptv($c) $bs] != -1} { lappend found $bs } {
                                if {[string equal bchans $t] && [string first # $bs] != 0} {
                                    putdcc $idx "\002AP\002: Invalid channel $bs, not adding..."
                                    continue
                                }
                                lappend unfound $bs
                                lappend aptv($c) $bs
                            }
                        }
                    }
                } {
                    putdcc $idx "\002AP\002: Invalid chan \002$c\002, either use a valid chan or 'global'."
                    return 0
                }
            } {
                foreach bs $l {
                    if {[lsearch -exact $aptv($c) $bs] != -1} { lappend found $bs } {
                        if {[string equal bchans $t] && [string first # $bs] != 0} {
                            putdcc $idx "\002AP\002: Invalid channel $bs, not adding..."
                            continue
                        }
                        lappend unfound $bs
                        lappend aptv($c) $bs
                    }
                }
            }
            if {[info exists unfound]} {
                foreach unfou [ww $unfound] {
                    putdcc $idx "\002AP\002: Succesfully added [join $unfou ,] to $c $t list."
                }
                sv
            }
            if {[info exists found]} {
                foreach fou [ww $found] {
                    putdcc $idx "\002AP\002: [join $fou ,] already exist in $c $t list."
                }
            }
        }
        "rem" {
            if {$ti == 0} {
                if {[validchan $c]} {
                    if {![info exists aptv($c)]} {
                        putdcc $idx "\002AP\002: $c $t list is empty."
                        return 0
                    } {
                        foreach bs $l {
                            if {[set sbs [lsearch -exact $aptv($c) $bs]] != -1} {
                                set aptv($c) [lreplace $aptv($c) $sbs $sbs]
                                lappend found $bs
                                if {$aptv($c) == {}} {unset aptv($c) ; break}
                            } { lappend unfound $bs }
                        }
                    }
                } {
                    putdcc $idx "\002AP\002: $c is an invalid channel, either use a valid chan or 'global'."
                    return 0
                }
            } {
                foreach bs $l {
                    if {[set sbs [lsearch -exact $aptv($c) $bs]] != -1} {
                        set aptv($c) [lreplace $aptv($c) $sbs $sbs]
                        lappend found $bs
                    } { lappend unfound $bs }
                }
            }
            if {[info exists unfound]} {
                foreach unfou [ww $unfound] {putdcc $idx "\002AP\002: [join $unfou ,] was not found in $c $t list."}
            }
            if {[info exists found]} {
                foreach fou [ww $found] {putdcc $idx "\002AP\002: Succesfully removed [join $fou ,] from $c $t list."}
                sv
            }
        }
        "list" {
            if {$ti == 0} {
                if {[validchan $c]} {
                    if {[info exists aptv($c)] && $aptv($c) != {}} {
                        foreach aplist [ww $aptv($c)] {putdcc $idx "\002AP\002: $c $t list: [join $aplist ,]"}
                    } {putdcc $idx "\002AP\002: $c $t list is empty." ; return 0}
                } {putdcc $idx "\002AP\002: Invalid chan \002$c\002, either use a valid chan or 'global'." ; return 0}
            } {
                if {$aptv($c) != {}} {
                    foreach aplist [ww $aptv($c)] {putdcc $idx "\002AP\002: $c $t list: [join $aplist ,]"}
                } {putdcc $idx "\002AP\002: $c $t list is empty."}
            }
        }
        "import" {
            if {[scan $arg "%s %s" oc ncs] != 2} {
                putdcc $idx "\002AP\002: SYNTAX: .ap:import <oldchan> <newchan>" ; return 0
            }
            foreach nc [string map [list * [channels]] $ncs] {
                if {[validchan $oc] && [validchan $nc]} {
                    foreach ci [channel info $oc] {
                        if {[string match ap:* [lindex $ci 0]]} {channel set $nc [lindex $ci 0] [lindex $ci 1]}
                    }
                    putdcc $idx "\002AP\002: Imported all AllProtection settings from $oc to $nc."
                } {putdcc $idx "\002AP\002: Failed! Make sure that $oc and $nc are valid channels."}
            }
        }
        "reset" {
            foreach c $chans {
                if {[validchan $c]} {
                    foreach u ${ap:udefs} {
                        if {[lindex $u 0] == "ap:level" && !$banthruX(do)} {continue}
                        channel set $c [lindex $u 0] [lindex $u 1]
                    }
                    putdcc $idx "\002AP\002: Reset all AllProtection settings on $c."
                } {putdcc $idx "\002AP\002: Failed! Make sure that $c is a valid channel."}
            }
        }
        "disable" {
            set OZ {ap:repeatc ap:clones ap:echans ap:partmsgs}
            set NV {ap:adv ap:swear ap:bnicks ap:drones ap:bidents ap:bchans ap:bctcrs ap:antispam}
            set CC {ap:codes ap:partmsgc}
            foreach c $chans {
                if {[validchan $c]} {
                    foreach u ${ap:udefs} {
                        if {[set ud [lindex $u 0]] == "ap:level" && !$banthruX(do)} {continue}
                        set rest [join [lrange [split [channel get $c $ud]] 1 end]]
                        if {[lsearch -exact $OZ $ud] != -1} {
                            channel set $c $ud "0 $rest"
                        } elseif {[lsearch -exact $NV $ud] != -1} {
                            channel set $c $ud "- $rest"
                        } elseif {[lsearch -exact $CC $ud] != -1} {
                            channel set $c $ud "r:0 b:0 u:0 c:0 [join [lrange [split [channel get $c $ud]] 4 end]]"
                        } elseif {[regexp {ap:(limit|level)} $u]} {
                            channel set $c $ud 0
                        } elseif {$ud == "ap:pqsadv"} {
                            channel set $c $ud "s:0 a:0"
                        } elseif {$ud != "ap:ctcpchecks"} {
                            channel set $c $ud "0:0 $rest"
                        }
                    }
                    putdcc $idx "\002AP\002: Succesfully disabled all AP protections on $c."
                } {putdcc $idx "\002AP\002: $c is an invalid channel (not in my chanlist)."}
            }
        }
        "monitor" {
            variable ptrig ; variable pwait
            if {[set pta [array get ptrig]]==""} {putdcc $idx "\002AP\002: No users currently under punishment."} {
                set fm 0
                foreach {uf ot} $pta {
                    foreach {c u f} [split $uf :] {break} ; foreach {o t} $ot {break}
                    if {[set dur [expr {$pwait-([unixtime]-$t)}]]>0} {
                        putdcc $idx "\002AP\002: \002$u\002 followed for \002$f\002 on \002$c\002. Offense: \002$o\002 (expires in \002$dur\002 secs)."
                        if {!$fm} {set fm 1}
                    }
                }
                if {!$fm} {putdcc $idx "\002AP\002: No users currently under punishment."}
            }
        }
        "priv" {
            set ptypes {ptextl ptextc pnotil pnotic pctcpf}
            switch -- [string tolower [lindex [split $arg] 0]] {
                "set" {
                    set pt [string tolower [lindex [split $arg] 1]]
                    if {[lsearch -exact $ptypes $pt] == -1 || ![regexp {^\d+:\d+$} [set v [lindex [split $arg] 2]]]} {
                        putdcc $idx "\002AP\002: SYNTAX: .ap:priv set <[join $ptypes /]> #:#" ; return 0
                    }
                    upvar [namespace current]::$pt privt
                    set privt(punish) $v
                    putdcc $idx "\002AP\002: Successfully set \002$pt\002 to \002$v\002."
                    sv
                }
                "list" {
                    foreach pt $ptypes {
                        upvar [namespace current]::$pt privt
                        putdcc $idx "\002AP\002: ${pt}: $privt(punish)"
                    }
                }
                default {putdcc $idx "\002AP\002: SYNTAX: .ap:priv <set/list> \[[join $ptypes /]\]."}
            }
        }
    }
}

proc sv {} {
    set apf [open scripts/aplists w]
    set lists {bchans bnicks bidents bwords adexempts droneexempts bctcrs adwords
        greetexempts ptextl ptextc pnotil pnotic pctcpf}
    foreach list $lists {
        variable $list
        foreach {apc apbc} [array get $list] {
            if {$apc != "global" && $apbc == {}} {continue}
            puts $apf "$list $apc [string trim [regsub -all {\s{1,}} $apbc " "]]"
        }
    }
    close $apf
}

proc rd {} {
    if {[file exists scripts/aplists]} {
        foreach apl [split [string tolower [read [set apf [open scripts/aplists]]]] \n][close $apf] {
            upvar [namespace current]::[lindex [split $apl] 0] apt
            set apt([set p [lindex [split $apl] 1]]) [set e [lrange $apl 2 end]]
            if {[regexp {^\d+:\d+$} [join $e]]} {set apt($p) [join $e]}
        }
    } {sv}
}

proc ptext {flood nick uhost hand arg} {
    switch -- $flood {
        "f" {
            variable ptextl ; variable ptextc
            foreach {ptxtll ptxtls} [split $ptextl(punish) :] {break}
            foreach {ptxtcl ptxtcs} [split $ptextc(punish) :] {break}
            if {[matchattr $hand fmo]} {return 0}
            if {($ptxtll > 0 && [follow $ptxtls ptxtl $ptxtll] != -1) || ($ptxtcl > 0 && \
                [follow $ptxtcs ptxtc $ptxtcl [string length $arg]] != -1)} {
                    privl MSG
            }
        }
        "adv" {
            foreach chan [channels] {
                if {[onchan $nick $chan]} { pubms adv $nick $uhost $hand $chan $arg }
            }
        }
    }
}

proc pctcp {flood nick uhost hand dest kw arg} {
    if {![isbotnick [lindex [split $dest @] 0]] || [string equal -nocase chat $kw]} {return 0}
    switch -- $flood {
        "text" {if {[isbotnick [lindex [split $dest @] 0]]} { ptext f $nick $uhost $hand $arg }}
        "ctcp" {
            variable pctcpf
            foreach {pctcpl pctcps} [split $pctcpf(punish) :] {break}
            if {$pctcpl <= 0 || [string equal -nocase action $kw] || [matchattr $hand fmo]} {return 0}
            if {[follow $pctcps pfctcp $pctcpl] != -1} {privl CTCP}
        }
    }
}

proc pnotc {nick uhost hand arg dest} {
    variable pnotil; variable pnotic
    foreach {pntll pntls} [split $pnotil(punish) :] {break}
    foreach {pntcl pntcs} [split $pnotic(punish) :] {break}
    if {[isbotnick [lindex [split $dest @] 0]] && ![matchattr $hand fmo]} {
        if {($pntll > 0 && [follow $pntls pnotl $pntll] != -1) || ($pntcl > 0 && \
            [follow $pntcs pnotc $pntcl [string length $arg]] != -1)} {
                privl NOTICE
        }
    }
}

proc pctcr {nick uhost hand dest kw arg} {
    if {![isbotnick [lindex [split $dest "@"] 0]]} {return 0}
    pctcp ctcp $nick $uhost $hand $dest $kw $arg
}

proc pflud {nick uhost hand type chan} {
    variable sfluds
    expr {$chan == "*" && $sfluds}
}

proc privl t {
    variable sfluds ; variable apfp ; variable bred ; variable ::botnick
    if {!$sfluds} {
        if {[string length $apfp(rmode)]==1} {
            if {!$bred} {
                putquick "MODE $botnick +$apfp(rmode)" -next
                if {$apfp(rtime) > 0} {
                    utimer $apfp(rtime) [namespace current]::remr
                }
                set bred 1
                putlog "\002AP\002: Set mode +$apfp(rmode) on me. ($t flood on me!)"
            }
        }
        set sfluds 1
        utimer $apfp(itime) [list set [namespace current]::sfluds 0]
        putlog "\002AP\002: Private botnet flood detected. Temporarly stopped answering recieved data."
    }
}

proc _k {jn c km bti {cc {incr cc}}} {
    # returns 0 if ccVar has been incremented
    if {[onchan $jn $c] && ![punishing k:$jn:$c]} {
        putquick "KICK $c $jn :[clonemap [mapall $km $c $bti] [uplevel 1 [split $cc]]]"
        return {set cc}
    }
    return {incr cc}
}

proc _b {jn ju c km bty bti arbVar {cc {incr cc}}} {
    # returns 0 if ccVar has been incremented
    upvar 1 $arbVar arb
    if {[info exists arb([set bm [masktype $jn!$ju $bty]])] || [punishing b:$bm:$c]} {return}
    variable banthruX; variable ::max-bans
    if {$banthruX(do)==2 || ($banthruX(do) && [llength [chanbans $c]] >= ${max-bans})} {
        putquick [mapXcmd $banthruX(cmd) $jn $ju $c [clonemap [mapall $km $c $bti] [uplevel 1 $cc]] $bty $bti]
        return {set cc}
    } {
        queue $c $bm
        if {$bti > 0 && [istimer "pushmode $c -b $bm"] == ""} {
            timer $bti [list pushmode $c -b $bm]
        }
        set arb($bm) 1
    }
    return {incr cc}
}

proc k {nl c km bty bti klm kty kti wm} {
    set cc 0
    foreach {jn ju} $nl {
        _k $jn $c $km 0
    }
}

proc b {nl c km bty bti klm kty kti wm} {
    set cc 0
    foreach {jn ju} $nl {
        _b $jn $ju $c $km $bty $bti arb
    }
}

proc kb {nl c km bty bti klm kty kti wm} {
    set cc 0
    foreach {jn ju} $nl {
        _b $jn $ju $c $km $bty $bti arb [_k $jn $c $km $bti]
    }
}

proc bk {nl c km bty bti klm kty kti wm} {
    set cc 0
    foreach {jn ju} $nl {
        _k $jn $c $km $bti [_b $jn $ju $c $km $bty $bti arb]
    }
}

proc w {nl c km bty bti klm kty kti wm} {
    variable wmeth; variable bnick; variable bident; variable eclones; variable bchan; variable bctcr
    set nsc [namespace current]
    if {[info exists eclones([string tolower $c:[lindex [split [lindex $nl 1] @] 1]])]} {
        utimer $eclones(caw) [list ${nsc}::joins clones [set tempn [lindex $nl end-1]] [lindex $nl end] [nick2hand $tempn $c] $c]
    }
    foreach {jn ju} $nl {
        if {[info exists bchan([set ch [string tolower $c:$ju]])]} {
            utimer $bchan(caw) [list ${nsc}::bchansw $jn $ju [nick2hand $jn $c] $c 0]
        } elseif {[info exists bctcr($ch)]} {
            utimer $bctcr(caw) [list ${nsc}::bchansw $jn $ju [nick2hand $jn $c] $c 1]
        } elseif {[info exists bnick($ch)]} {
            utimer $bnick(caw) [list ${nsc}::joins bnicks $jn $ju [nick2hand $jn $c] $c]
        } elseif {[info exists bident($ch)]} {
            utimer $bident(caw) [list ${nsc}::joins bidents $jn $ju [nick2hand $jn $c] $c]
        }
        if {![punishing w:$jn:$c]} {
            puthelp "$wmeth $jn :$wm"
            lappend offenders $jn
        }
    }
    if {[info exists offenders]} { putlog "\002AP\002: Warned [join $offenders \002,\002] on $c: $wm" }
}

proc kl {nl c km bty bti klm kty kti wm} {
    variable kline
    foreach {jn ju} $nl {
        if {![info exists ark([set klmask [scan [masktype $jn!$ju $kty] {%*[^!]!%s}]])]} {
            if {![punishing kl:$klmask:$c]} {
                putquick [string map [list %mask $klmask %time $kti %reason $klm] $kline(cmd)]
                set ark($klmask) 1
            }
        }
    }
}

proc kil {nl c km bty bti klm kty kti wm} {
    foreach {jn ju} $nl {
        if {![punishing kil:$jn:$c]} {
            putquick "kill $jn $klm"
        }
    }
}


proc punish {pm nl c km wm bty bti klm kti kty fv} {
    variable pwait; variable kline; variable ptrig
    if {$kti < 0} { set kti $kline(time) }
    set fv $c:$fv
    if {![info exists ptrig($fv)] || [unixtime]-[lindex $ptrig($fv) 1] > $pwait} {
        set ptrig($fv) [list 0 [unixtime]]
    }
    set o [lindex $ptrig($fv) 0]
    set ol [llength [split $pm :]]
    if {$o > $ol - 1} { set o [expr {$ol - 1}] }
    pcount $pwait ptrig($fv)
    switch -- [set p [string tolower [lindex [split $pm :] $o]]] {
        "k" - "b" - "kb" - "bk" - "w" - "kl" - "kil" {
            $p $nl $c $km $bty $bti $klm $kty $kti $wm
        }
        "v" { }
        default {
            error "\002AP\002: Invalid punishment \002$p\002, must be one of v, w, k, b, kb, bk, kl, kil"
        }
    }
    return 0
}

proc checkscans {} {
    variable Sec; variable apqueue; variable antiSpamOnline
    if {[istimer [namespace current]::dumpqueues utimers]==""} {
        set startTimer 0
        if {$apqueue(time) > 0 || [info exists antiSpamOnline]} {
            set startTimer 1
        }
        if {$startTimer} {
            set Sec -1
            utimer 1 [namespace current]::dumpqueues
        }
    }
    foreach ss {ap:bctcrs ap:bchans ap:echans} {
        foreach c [channels] {
            if {![info exists scanned($c)]} {set scanned($c) 0}
            if {!$scanned($c)} {set scanned($c) [activt [string tolower $c] $ss]}
        }
    }
}

proc activt {c ss} {
    set got [split [channel get $c $ss]]
    set i 0
    set ns [namespace current]
    if {[vcg $c $ss]} {
        if {![string is integer -strict [set ce [lindex $got 0]]]} {
            if {$ce == "+" && [set t [lindex $got end]] > 0} {
                set st 1
                if {[istimer "${ns}::scanc $c $ss"]==""} { timer $t [list ${ns}::scanc $c $ss]; set i 1 }
            }
        } elseif {$ce > 0 && [set t [lindex $got end]] > 0} {
            set st 1
            if {[istimer "${ns}::scanc $c $ss"]==""} { timer $t [list ${ns}::scanc $c $ss] }
        }
    }
    if {[info exists st] && [istimer [namespace current]::dumpqueues utimers]==""} {
        variable Sec
        set Sec -1
        utimer 1 [namespace current]::dumpqueues
    }
    set i
}

proc scanc {c ss} {
    variable scanq
    set got [split [channel get $c $ss]]
    set scan 0
    if {[vcg $c $ss]} {
        if {![string is integer -strict [set ce [lindex $got 0]]]} {
            if {$ce == "+" && [lindex $got end] > 0} {set scan 1}
        } elseif {$ce > 0 && [lindex $got end] > 0} {set scan 1}
        if {$scan} {
            set scanq($c) {}
            foreach n [chanlist $c] {
                if {[invalid:apc $n [set h [nick2hand $n $c]] $c]} {continue}
                lappend scanq($c) [list $n [getchanhost $n $c] $h [expr {[regexp {ap:[be]chans} $ss]?0:1}]]
            }
            activt $c $ss
        }
    }
}

proc ezilamn str {
    set str2 ""
    for {set i [string length $str]} {$i > 0} {incr i -1} {
        append str2 [string index $str [expr {$i - 1}]]
    }
    set str2
}

proc vcg {c cg} {
    if {$cg == "ap:ctcpchecks"} {return [expr {[channel get $c $cg] != ""}]}
    if {$cg == "ap:pqsadv"} {return [string match -nocase {s:[01] a:[01]} [channel get $c $cg]]}
    set L5 {ap:bchans ap:echans ap:bctcrs}
    set L7 {ap:codes ap:partmsgc}
    set lgot [llength [set got [split [channel get $c $cg]]]]
    if {[lsearch $L5 $cg] != -1} {
        if {$lgot != 5} {return 0} ; set i 1
    } elseif {[lsearch $L7 $cg] != -1} {
        if {$lgot != 7} {return 0} ; set i 4
    } elseif {[regexp {ap:(limit|level)} $cg]} {
        if {$lgot != 1} {return 0} ; set i 0
    } {
        if {![regexp {ap:(b[^i]|massj)} $cg] || $cg == "ap:bnicks"} {
            if {$lgot != 4} {return 0} ; set i 1
            if {$cg == "ap:antispam"} {
                set i 2
            } elseif {[regexp {ap:(repeatc|partmsgs|revdoor|clones|echans)} $cg] && ![string is integer -strict [lindex $got 0]]} {
                return 0
            }
        } {set i end}
    }
    expr {[string is integer -strict [lindex $got $i]]&&[string is integer -strict [lindex $got end]]}
}

proc init c {
    variable ap:udefs; variable banthruX
    foreach u ${ap:udefs} {
        if {[lindex $u 0] == "ap:level" && !$banthruX(do)} {continue}
        if {![vcg $c [lindex $u 0]]} {channel set $c [lindex $u 0] [lindex $u 1]}
    }
    foreach budef {ap:btextl ap:btextc ap:bnotcl ap:bnotcc ap:bctcp ap:massjoin ap:brevdoor
    ap:bpartmsg ap:bnickf ap:bcodes} {
        append olm [lindex [split [lindex [split [channel get $c $budef]] 1] -] 0]
    }
    foreach lm [lsort -unique [split $olm ""]] {
        if {[lsearch [binds mode] "* {\\\* -$lm} *"] == -1} {
            bind mode - "* -$lm" [namespace current]::resetbtc
        }
    }
}

proc remr {} {
    variable bred; variable apfp; variable ::botnick
    puthelp "MODE $botnick -$apfp(rmode)"
    putlog "\002AP\002: Removed +$apfp(rmode) from me."
    set bred 0
}

proc lockc {c m tl ty} {
    variable btclocked; variable notifyusers
    if {![info exists btclocked($c)]} {set btclocked($c) 0}
    if {!$btclocked($c)} {
        dolock $c $m
        if {$tl > 0} {
            utimer $tl [list [namespace current]::btcunlock $c $m btclocked($c)]
        } {utimer 90 [list [namespace current]::resetbtc * * * $c]}
        set btclocked($c) 1
        if {$btclocked(lnotc) != ""} {
            puthelp "NOTICE $c :$btclocked(lnotc)"
        }
        putlog "\002AP\002: Locked $c due to $ty."
        if {$notifyusers != {}} {foreach nuser $notifyusers {sendnote AP $nuser "$ty detected on $c."}}
    }
}

proc dolock {c lm} {
    set mode "MODE $c +"
    foreach m [split $lm] {append mode "$m "}
    putquick [string trim $mode] -next
}

proc resetbtc args {
    variable btclocked
    set btclocked([string tolower [lindex $args 3]]) 0
}

proc btcunlock {c ms lv} {
    upvar [namespace current]::$lv locked
    if {![info exists locked] || $locked} {set locked 0}
    foreach mode [split $ms ""] {
        if {[string equal "-" $mode]} {break}
        if {[regexp $mode [lindex [split [getchanmode $c]] 0]]} {pushmode $c -$mode}
    }
}

proc droneb {n u c bti pm bty mapr} {
    variable drone
    if {![string is integer -strict $pm]} {
        punish $pm [list $n $u] $c [mapr $drone(kmsg) $mapr] $drone(wmsg) $bty $bti $drone(klmsg) $drone(ktime) $drone(ktype) [string tolower $u]:drone
    } {
        if {![punishing k:$n:$c $pm]} {putquick "KICK $c $n :[mapall [mapr $drone(kmsg) $mapr] $c 0]"}
    }
    putlog "\002AP\002: DRONE: Detected \002$n\002!\002[scan $u {%[^@]}]\002 on \002$c\002."
}

proc seqflood {f o s n u c pm bty bti sla} {
    variable following
    if {[invalid:apf $o $s]} {return 0}
    set uhc $f:[string tolower $u:$c]
    set myo ""
    if {[regexp {textc|notcc} $f]} {
        if {[info exists following($uhc)]} {set myo [lindex $following($uhc) 0]}
        set i $sla; set rsn {$myo chars}
    } {set i 1; set rsn {$o lines}}
    checkf $s $o $uhc $u $c $pm $n $rsn $bty $bti $f $i $myo
}

proc follow {s fv pun {v 1} {ty 0}} {
    variable following
    if {![info exists following($fv)]} {
        set o $v
        set t [clock clicks -milliseconds]
    } {
        foreach {o t} $following($fv) {break}
        incr o $v
    }
    if {[set z [expr {([clock clicks -milliseconds]-$t)/1000.}]] >= $s} {
        set o $v
        set t [clock clicks -milliseconds]
    }
    set following($fv) [list $o $t]
    if {$o >= $pun} {if {!$ty} {followrem following($fv)} ; return [expr {$z>=$s?0.0:$z}]}
    return -1
}

proc pcount {v var} {
    upvar [namespace current]::$var p
    foreach {o t} $p {break}
    set p [expr {[unixtime]-$t <= $v?[list [incr o] [unixtime]]:[list 1 [unixtime]]}]
}

proc punishing {i {s 0.25}} {
    variable punishing
    set s [expr {int($s*1000)}]
    set i [string tolower $i]; set t [clock clicks -milliseconds]
    if {[info exists punishing($i)] && $punishing($i) > $t} {set i 1} {
        set punishing($i) [expr {$t+$s}]
        set i 0
    }
}

proc followrem fv {
    upvar [namespace current]::$fv f
    if {[info exists f]} {unset f}
}

proc Nfollow {t tl n u} {
    upvar [namespace current]::$tl f
    lappend f $n $u
    utimer $t [list [namespace current]::Nfollowrem $tl $n $u]
}

proc Nfollowrem {tl n u} {
    upvar [namespace current]::$tl bl
    if {[info exists bl]} {
        set bl [lreplace $bl [set i [lsearch -exact $bl $n]] $i]
        set bl [lreplace $bl [set i [lsearch -exact $bl $u]] $i]
        if {$bl == {}} {unset bl}
    }
}

proc asb:queue {n t} {variable antispam; lappend antispam(q) $n $t}

proc mapall {s c b} {
    string map [list %date [ctime [unixtime]] %chan $c %kcount [getkcount] %btime $b] $s
}

proc clonemap {k c} { string map [list %ic $c] $k }

proc mapr {m r} { string map [list %rate $r] $m }

proc getkcount {} {incr [namespace current]::NumKicks}

proc cgsplit off {
    foreach {o s} [split $off :] {break}
    expr {([info exists o]&&[info exists s])?[list $o $s]:{0 0}}
}

proc invalid:apf {o s} {
    expr {![string is integer -strict $o] || $o <= 0 || ![string is double -strict $s] || $s <= 0}
}

proc icodes str { regexp {r:\d{1,3}\sb:\d{1,3}\su:\d{1,3}\sc:\d{1,3}} $str }

proc invalid:apc {n h c} {
    variable exmptype
    if {[isbotnick $n] || ![botisop $c] || [matchattr $h n|n $c]} {return 1}
    set true 0
    foreach t $exmptype {
        switch -- [string tolower $t] {
            "ops" {set true [isop $n $c]}
            "voices" {set true [isvoice $n $c]}
            "halfops" {set true [ishalfop $n $c]}
            default {set e $t}
        }
        if {$true} {break}
        if {[info exists e]} {
            if {[regexp {[+-].+[|&][+-].+} $e]} {
                if {[set true [matchattr $h $e $c]]} {
                    break
                }
            } {
                error "Invalid exempt type ($e)."
            }
        }
    }
    set true
}

proc nap:chan {c cl} {
    expr {!($cl == "*" || [lsearch -exact [split [string tolower $cl]] [string tolower $c]] != -1)}
}

proc masktype {nuh {t 3}} {
    if {[scan $nuh {%[^!]!%[^@]@%s} n u h]!=3} {
        error "Usage: masktype <nick!user@host> \[type\]"
    }
    if {$t == 10} {return *!$u@*}
    if {$t == 11} {return $n!*@*}
    if {[string match {[3489]} $t]} {set h [lindex [split [maskhost $h] @] 1]}
    if {[string match {[1368]} $t]} {set u *[string trimleft $u ~]} elseif {[string match {[2479]} $t]} {set u *}
    if {[string match {[01234]} $t]} {set n *}
    set nuh $n!$u@$h
}

proc ww l {
    set cur {}
    foreach word [set l][unset l] {
        if {[llength $cur]==10} {
            lappend out $cur
            set cur [list $word]
        } { lappend cur $word }
    }
    lappend out $cur
}

proc cf str { string map {\017 ""} [stripcodes bcruag $str] }

proc queue {c b} {
    variable apqueue
    if {$apqueue(time) < 1} {putquick "MODE $c +b $b"} {
        lappend apqueue([string tolower $c]) $b
    }
}

proc mapXcmd {cmd n u c k ty ti} {
    string map [list %reason $k %level [channel get $c ap:level] %btime [expr {$ti/60}] \
        %ban [masktype $n!$u $ty] %nick $n %chan $c] $cmd
}

proc dumpqueues {} {
    variable apqueue; variable Sec; variable antispam
    if {[incr Sec]>59} {set Sec 0}
    if {$apqueue(time) > 0 && $Sec % $apqueue(time) == 0} {
        variable ::modes-per-line
        foreach c [channels] {
            if {![info exists apqueue([set c [string tolower $c]])] || $apqueue($c) == {}} {continue}
            for {set i 0} {$i<[llength [set apqueue($c) [lsort -unique $apqueue($c)]]]} {incr i} {
                set bans [lrange $apqueue($c) $i [incr i [expr {${modes-per-line}-1}]]]
                putquick "MODE $c +[string repeat b [llength $bans]] [join $bans]" -next
            }
            set apqueue($c) {}
        }
    }
    if {$Sec % 2 == 0 && [info exists antispam(idx)] && [valididx $antispam(idx)]} {
        if {[info exists antispam(q)]} {
            foreach {n t} $antispam(q) {
                putdcc $antispam(idx) "privmsg $n :$t"
            }
        }
        set antispam(q) {}
    }
    if {$Sec % 3 == 0} {
        variable scanq
        foreach {c l} [array get scanq] {
            set i 0
            foreach e $l {
                foreach {n u h t} $e {break}
                set scanq($c) [lrange $l [incr i] end]
                bchansw $n $u $h $c $t
                if {$i == 10} {break}
            }
        }
    }
    utimer 1 [namespace current]::dumpqueues
}

proc checkf {s o var u c pm n mapr bty bti ft {v 1} {myo ""}} {
    upvar [namespace current]::$ft myvar
    if {[set ts [follow $s $var $o $v]] != -1} {
        if {$myo == ""} {set myo $v} {incr myo $v}
        punish $pm [list $n $u] $c [mapr $myvar(kmsg) "[subst $mapr] in $ts secs"] $myvar(wmsg) $bty $bti $myvar(klmsg) $myvar(ktime) $myvar(ktype) [string tolower $u]:$ft
    }
}

proc checklc {s var o c ms lt r {v 1}} {if {[follow $s $var $o $v] != -1} {lockc $c $ms $lt "Botnet $r flood"}}

proc cl s {
    set is 0; set res [set tem ""]
    foreach e [split $s] {
        if {!$is} {
            if {![regexp {^"} $e]} { lappend res $e } {
                    if {[regexp {"$} $e]} {lappend res [string range $e 1 end-1]} {
                    append tem "[string range $e 1 end] "
                    set is 1
                }
            }
        } {
            if {[regexp {"$} $e]} {
                append tem [string range $e 0 end-1]
                lappend res $tem ; set tem ""; set is 0
            } {append tem "$e "}
        }
    }
    set res
}

proc aplog str {
    variable logkbs
    lappend logkbs(logs) $str
}

proc unload type {
    variable logkbs; variable antispam; variable _VERSION
    foreach t {timer utimer} {
        foreach ti [${t}s] {
            if {[string match [namespace current]::* [lindex $ti 1]]} {kill$t [lindex $ti 2]}
        }
    }
    if {[info exists logkbs(logs)]} {
        set f [open $logkbs(file) w]
        foreach log $logkbs(logs) { if {$log != ""} { puts $f $log } }
        close $f
    }
    if {[info exists antispam(idx)] && [valididx $antispam(idx)]} {
        putdcc $antispam(idx) "part ,"
        killdcc $antispam(idx)
    }
    load unbind
    namespace delete [namespace current]
    putlog "\002A\002ll\002P\002rotection v$_VERSION successfully unloaded..."
}

if {[llength [channels]] == 0 && [llength [userlist]] == 0} {
    bind evnt - loaded [namespace current]::load
} {
    load
}
}
