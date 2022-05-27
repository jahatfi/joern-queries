# Joern Static Analysis

## Disclaimer
I am not officially affiliated with the [Joern project](https://joern.io/) in any way, nor its paid counterpart, [ShiftLeft](https://www.shiftleft.io/), I'm just a static analysis enthuastist and developer suffering from imposter syndrome every day.

## Special Thanks
A special thanks to the friendly [Joern team on Discord](https://discord.gg/vv4MH284Hc), they've been super helpful and provided valuable tips for troubleshooting as I was getting started.

## Joern Overview
As stated on [Joern's documentation page](https://docs.joern.io/home), Joern is scala-based static analysis tool that uses code property graphs to enable security audits of source code. These graphs can be queried to answer questions or determine facts about the program under analysis.  In order to not restate existing information, I strongly encourage you to check out the [resources listed below](#resources).  Note: there is some overlap in the material presented but the repeition can be helpful when learning Joern.

## Joern Workshops
The free Joern workshop does a great job of introducing the concepts of Joern, and walks the user through the process of getting started, all the way to intermediate queries.  I will recommend the reader review it rather than reinvent the wheel here.  Note that both workshops in the repo below are nearly identical, and one need only go through one of them.
[Joern workshop material](https://github.com/joernio/workshops)

## More intermediate examples
So as not to call my own examples "advanced", I'll offer that I think the queries in [my notes](joern_notes.scala) are at least intermediate in difficulty.  I've not yet found the capability they offer anywhere else on the internet, and they took me a bit to develop on my own, so I assume they're non-trivial for a beginner.   That all said, I do my best to walk the reader through the process of developing them in order to encourage further work and creating one's own Joern queries.  Jump over to those notes to see if there's anything you can learn!

## Other resources
I found these resources invaluable when learning Joern and creating my own queries.  I hope they help you as much as they helped me!
1. [Joern homepage](https://joern.io/)  
2. [Joern's documentation page](https://docs.joern.io/home)  
3. [Joern's Code Propery Graph Specification](https://cpg.joern.io/)
4. [Joern's database of pre-written queries](https://queries.joern.io/)
5. [Jaiverma's Intro to Joern](https://jaiverma.github.io/blog/joern-intro) There are more resources linked at the bottom of that page.
6. [Praetorian's Blog: 'Why You Should Add Joern to Your Source Code Audit Toolkit'](https://www.praetorian.com/blog/why-you-should-add-joern-to-your-source-code-audit-toolkit/)
6. [CYS4: Nicola Vella and Alessio Pizza's Blog: 'From Patch To Exploit: CVE-2021-35029'](https://blog.cys4.com/exploit/reverse-engineering/2022/04/18/From-Patch-To-Exploit_CVE-2021-35029.html)