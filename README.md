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

## Joern Limitations and Dark Magic for Overcoming Them
At this time the data flow offered by Joern's reachableBy* functions (promoted in most examples and blogs) appears to only work at the function level. It appears incapable of distinguising between function arguments.  This is not an issue for sources and sinks that only take one arguments (e.g. `gets()`, `system()`, respectively) but lacks the abiility to avoid false positives if seeking to use a specific argument as a source or sink, e.g. the `buf` argument of `recv()`.  In a non-trivial program I believe (though without proof) that this could yield too many false positives to be of signifant use for complex analysis of non-trivial programs.  It's my view that analysis would be limited to simpler queries to avoid the workload of manually analyzing the results to determine which ones are true positives.  Yet such an approach could miss significant software flaws.

Here's specifically what I've found:

Say I want to see if argument 1 to `system()` is ever reachable by argument 2 of `source_4()`; I do **not** care if any other path exists between *any* other pair of source/sink argument pairs (note that there are no other arguments so this isn't a great example to show other sink options.) 

I would define the sink like so:
`def sink = cpg.call.name("system").argument.order(1)`
Next, assume that I wish to treat the `buff` argument (2nd argument) of `recv()` as a source. Neither approach shown below has worked for defining the source with either `reachableBy/reachableByFlows` function:

`def src = cpg.method.name("my_source").parameter.order(2)`
`def src = cpg.call.name("my_source").argument.order(1)`


Neither approach seems to work as desired.  The `reachableBy/reachableByFlows` functions return results for **all** argument permutations, e.g. if the argument to `system()` is reachable by argument 1 of `source_4()`, but **that is an undesirable result**.  

I have contacted the Joern team to determine if I misunderstand Joern's capabilities; perhaps my assessment of Joern's limitation as stated above is incorrect?  In the meantime, I propose a "Dark Magic" solution to address this limitation in the context of my own work. By "Dark Magic" I simply mean that I think the approach is some combination of a hack, a creative solution, not what the creators have in mind, yet still hopefully effective. 


My "Dark Magic" approach starts with the results from the approach shown above.  It then traces the use of tainted variables from the results provided to determine if the specific source->sink path exists, thereby filtering out the false positives.   I need to make sure this algortihm is aware of the dependencies enumerated below.  Note that I borrow the dependency terminology from [8].  Of course, as this program analyzes code above assembly level the terminology here differs slightly compared to its use in that paper, which is focuses on assembly code.  For example, the authors use the terms "load"/"store", which are mapped to "source"/"destination" in points 3 & 4 below.  See sections 4.1 for more details.  Finally, note that [8] uses the term 'spurious' data instead of 'tainted', but  [9,10] use the term 'tainted', which is preferred here. They mean the exact same thing in this context.

1. Copy dependencies: If tainted variable buff is copied to buff2, buff2 is then treated as tainted:
    ```c
        char buff[100];
        char *buff2;
        buff = fgets(buff);  //buff is now tainted
        buff2 = &buff[0];    //buff2 is now tainted
    ```
2. Computation dependency: Any computation that depends on a tainted value is also considered tainted
    ```c
        int i;
        scanf("%d", &i);  //i is tainted
        long j = i + 0xdeadbeef;  //j depends on i, and is thus tainted here
    ```
3. Load-address Dependency: A tainted variable is used as a source pointer when copying data.  (If such an operation is even allowed; it could easily result in a segmentation fault.)
    ```c
        unsigned char dest[100];
        int i;
        scanf("%d", &i);  //i is tainted
        memcpy(dest, (void*) &i, 100); //dest is tainted, as it contains data copied FROM a tainted address.
                                       //Thus, the content in dest cannot be predicted.
    ```
4. Store-address Dependency: A tainted variable is used as a pointer when data is copied TO a tainted address.  The analyzed program cannot know that the data at the tainted address would change.  (If such an operation is even allowed; more than likely it will result in a segmentation fault.)
    ```c
        char source[] = "Hello World";
        int dest;
        scanf("%d", &dest);  //dest is tainted
        memcpy((char *) &dest, (char *)&source, ); //The content at address *dest is tainted, as that address was not expected to change.
    ```

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
7. [CYS4: Nicola Vella and Alessio Pizza's Blog: 'From Patch To Exploit: CVE-2021-35029'](https://blog.cys4.com/exploit/reverse-engineering/2022/04/18/From-Patch-To-Exploit_CVE-2021-35029.html)
8. Secure Program Execution via Dynamic Information Flow Tracking: http://csg.csail./mit.edi/pubs/memos/memo-467.pdf
9. LATCH: A Locality Aware Taint Checker: http://www.cs.ucr.edu/~nael/pubs/micro19.pdf
10. Clang Documentation: https://clang.llvm.org/docs/analyzer/checker.html#alpha-security-taint-taintpropagation-c-c
11. Data-flow Analysis https://en.wikipedia.org/wiki/Data-flow_analysis
12. DHS CISA Website - Source Code Analysis Tools - Example Programs (No longer maintained) https://us-cert.cisa.gov/bsi/articles/tools/source-code-anaysis/source-code-analysis-tools--example-programs
