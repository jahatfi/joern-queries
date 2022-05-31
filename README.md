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

## Workshop
The accompanying file "layer.c" is used in these examples.
Follow the instructions for installing Joern (https://docs.joern.io/home), then:
In a terminal, start Joern, e.g.  
`joern`  
import the code, e.g.  
`importCode("layers.c")`  
Run the dataflow command  
`run.ossdataflow`  
Save the CPG:  
`save`  

Find paths from a "gets" source to a "system" sink
With more recent versions of Joern, we must specify exactly which arguments
we want data flow for:
cpg.call.name("system").argument(1).reachableByFlows(cpg.call.name("gets").argument(1)).p 

From this point forward, I will demonstrate intermediate Joern queries that I 
will treat as primitive to ultimately combine into on large primary query.  Let's jump in.
```scala
// Find paths from a "gets" source to a "system" sink
// With more recent versions of Joern, we must specify exactly which arguments
// we want data flow for:
cpg.call.name("system").argument(1).reachableByFlows(cpg.call.name("gets").argument(1)).p 
```

```scala
// Rewrite the above more generically by providing 4 args:
// 1. Provide the name of a function that taints its arguments by calling a source.
//    Assume all arguments tainted for now.  I address this assumption later;
//    I will show how to automatically find EXACTLY which arguments are tainted.
//    I used "source_3" because it taints its first arg via a call to "gets".
//    Granted, this requires work to find, but again, I will show how to ID automatiically later.
// 2. The source function that taints a parameter pointer, e.g. "gets", "recv", etc
// 3. The index of the tainted sink parameter.  "gets" taints the first (and only)
//    parameter, so this would be 1.  If I wanted to "recv" as my sink, I'd used 2.

// You can pick and source+sink pair you like, but using this, you do need to ID the first argument manually.  
// "That's what I'm trying to avoid!" you say.  Indeed.  Keep reading. :)

// Note that this was an early prototype. You can skip it if you find it hard to understand, 
// but I encourage you to at least run the query as shown.
// I provide more advanced versions of this function later on.
def getSinglePath(function_that_taints_param_ptr:String, source:String, tainted_index:Int, sink_first_arg:String) = {  
    //val function_that_taints_param_ptr = "source_3"  
    val source_params = cpg.method.name(function_that_taints_param_ptr).parameter  
    val filteredParams = source_params.filter(  
        param => {
            val sink = cpg.method.ast.isCallTo(source).argument(tainted _index)
            sink.reachableBy(param)
        }.size > 0
    )
    try{
        val index_of_tainted_param = filteredParams.index.head  
        val src = cpg.call.name(function_that_taints_param_ptr).argument.order  (index_of_tainted_param)  
        val sink = cpg.call.name(sink_first_arg)  
        sink.reachableByFlows(src).p  
    }catch{  
        case x: NoSuchElementException =>{  
            println("No path from " + source + "(...) to " + function_that_taints_param_ptr + "(...) found")  
        }  
    }  
}  
```
Enter the function above, then try this:
```scala
getSinglePath("source_3", "gets", 1, "system")`  
getSinglePath("source_4", "recv", 2, "system")`  
```

Moving on to another example. Not only does this work for sources that taint parameter pointers,
but it ALSO works for functions that taint returned pointers.
Note that this yields false positives.  A more accurate version is presented much later in this document
but this shows the general idea without the complexity required to avoid unreachable code.
```scala
def getAllPaths(sources:ListBuffer[(String, String, Int)], sinks:List[(String,Int)]):ListBuffer[List[String]] = {
    val results:ListBuffer[List[String]] = ListBuffer()
    for((caller, source, taintedIndex) <- sources){
        for((sink, sinkIndex) <- sinks){
            print("Checking " + caller + "(" + taintedIndex + ")->" + sink+"("+sinkIndex+")\n")
            // TODO: Fix the fact that this is getting unreachable code :(
            val thisSrc = cpg.call.name(caller).argument.order(taintedIndex)
            val thisSink = cpg.call.name(sink).argument.order(sinkIndex)
            val paths = thisSink.reachableByFlows(thisSrc).p
            println(paths)
            if(paths.length > 0){
                results += paths
            }
        }
    }
    return results
}
```
Enter the function above, then try this:  
```scala
val mySources = ListBuffer(("gets", "n/a", 1))
val mySinks = List(("system",1))
getAllPathsv1(mySources, mySinks)
```
It should return 3 results, but note that sink_3 is never called.
```scala
// Here's the full version we'll use moving forward.
import scala.collection.mutable.ListBuffer 
def getAllPaths(sources:ListBuffer[(String, String, Int)], sinks:List[(String,Int)]):ListBuffer[String] = {
    val results:ListBuffer[List[String]] = ListBuffer()
    for((caller, source, taintedIndex) <- sources){
        for((sink, sinkIndex) <- sinks){
            print("Checking " + caller + "(" + taintedIndex + ")->" + sink+"("+sinkIndex+")\n")
            // Ideally we'd only need the 3 lines below to trace any path from any source 
            // to any sink.  This code takes into account the exact parameters that are tainted (my contribution), 
            // including return values (native to Joern.)
            // That said, it yields results with both duplicate lines AND unreachable code.
            // E.g. When analyzing layers.c,  it yields sink_3() as a
            // complete source->sink path, yet sink_3 is never called from anywhere!
            def thisSrc = cpg.call.name(caller).argument(taintedIndex)
            def thisSink = cpg.call.name(sink).argument(sinkIndex)
            def paths = thisSink.reachableByFlows(thisSrc).p

            // This whole mess below is designed to exclude unreachable code.
            // The code below does not trace flow paths by specific arguments,
            // so in that way it's less complete (more false positives related to 
            // tracing arguments that might not be accurate), yet at the same time 
            // I found this same approach to avoid dead code (more sound) more so 
            // than the approach above.
            println(paths)
            print("Checking flow to any args: any args: " + caller + "(...)->" + sink+"(...)\n")
            def paths2 = cpg.call.name(sink).reachableByFlows(cpg.call.name(caller)).p
            println(paths2)

            // So now I have two lists of possible paths.
            // Paths is more specific, but maybe with some false positives.
            // Start there: we only have more work to do if there's at least one result in paths:
            if(paths.length > 0){
                // Per my own convention, if the source is "n/a", it's a regular source function 
                // (e.g. gets) that Joern can handle natively. Just add paths2 and move on.
                // TODO Or is it += paths???
                if(source != "n/a"){
                    results += paths2
                    println("Nope")
                }
                else{
                    // This is a function that returns tainted parameters and the 
                    // requires the complex analysis below.
                    // First, remove duplicate lines from both paths(2).  
                    // This is gonna be ugly :(
                    val dedupPaths2:ListBuffer[String] = ListBuffer()
                    for(path2 <- paths2){
                        for(line <- path2.split("\\n")){
                            if(!dedupPaths2.contains(line.trim() + "\n")){
                                dedupPaths2 += line.trim() + "\n"
                            }
                        }                        
                    }                        
                    for(path <- paths){
                        val dedupPaths:ListBuffer[String] = ListBuffer()
                        for(line <- path.split("\\n")){
                            if(!dedupPaths.contains(line.trim() + "\n")){
                                dedupPaths += line.trim() + "\n"
                            }
                        }
                        // This path in paths has been deduplicated (duplicates removed)
                        // If the same path exists in paths2 (also deduplicated), I am 
                        // more confident that this path is NOT a false positive.
                        // Save it to the results
                        val newPaths = (dedupPaths intersect dedupPaths2)
                        results += newPaths.l                 
                    }
                }
            }
        }
    }
    val results2:ListBuffer[String] = ListBuffer()
    for(r <- results){
        results2 += r.mkString
    }
    return results2
}
```
After defining the function above, run the above like so:
```scala
val mySources = ListBuffer(("gets", "n/a", 1))
val mySinks = List(("system",1))
getAllPaths(mySources, mySinks)
```

## Misc Notes
Ideally, a proper data flow analysis is aware of the dependencies enumerated below.  Note that I borrow the dependency terminology from [8].  Of course, as this program analyzes code above assembly level the terminology here differs slightly compared to its use in that paper, which is focuses on assembly code.  For example, the authors use the terms "load"/"store", which are mapped to "source"/"destination" in points 3 & 4 below.  See sections 4.1 for more details.  Finally, note that [8] uses the term 'spurious' data instead of 'tainted', but  [9,10] use the term 'tainted', which is preferred here. They mean the exact same thing in this context.

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
