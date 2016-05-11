# allprotection
An All-Around Protection Script for Eggdrops

This Eggdrop script was first conceived some time around 2005 and has since developed into the ultimate public/private/ircnet protection script. Given that I'm no longer actively manintaining it, I've decided to move it to my Github page to facilitate contributions by other developers.

## Features

- text floods (action or msg)
- repeat floods
- notice floods
- codes floods
- ads, bad words, and private spam
- bad nicks/idents (on join and change)
- join floods
- revolving door (fly-bys)
- nick floods
- random nicks ban (drones)
- takeovers (mass deop/ban/kick)
- channel limit
- ctcp/ctcr floods
- part msg floods
- clones
- bad channels
- excess channels
- bad CTCP-replies
- Anti-spam bot (cycler)

### Botnet flood protections:
- mass text floods.
- mass notice floods.
- mass ctcp/ctcr floods.
- mass join floods.
- mass revolving door floods.
- mass part msg floods.
- mass nick floods.

### Private flood protections
- Private text floods.
- Private notice floods.
- Private ctcp/ctcr floods.

Settings are highly configurable, giving the ability to specify different punishment modes (warn/kick/ban) as well as apply channel-specifc settings.

#### exempt methods:

    # 0: Neither voices nor halfops are exempted from punishment
    # 1: Voices are exempted from punishment
    # 2: Halfops are exempted from punishment
    # 3: Both halfops and voices are exempted from punishment

Users with **+f** and **+mo** flags are exempted by default from any punishment.

#### Available punishment methods:

    # v: Void - do nothing
    # w: Warn offender
    # k: Kick offender
    # b: Ban offender
    # kb: Kick + Ban offender
    # kl: KLine offender
    # kil: Kill offender
    #
    ## You can use them like this for example:
    # w:k:kb
    # this means, first Warn then Kick then Kickban. (if offence is repeated ofcourse)
    ## these steps will be triggered if the offences happend during <pwait> seconds.
    # NOTE: These methods are not applicable on all flood types. I only applied this
    # feature on the flood types I think they're needed.

Details are provided inside the script.

Discussion about the script (as well the history of its development): http://forum.egghelp.org/viewtopic.php?t=9721
