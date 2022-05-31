// References: 
//https://jaiverma.github.io/blog/joern-uboot
//https://jaiverma.github.io/blog/joern-intro
//https://snoopysecurity.github.io/software-security/2021/12/08/joern-cheat-sheet.html

// The accompanying file "layer.c" is used in these examples.
// Follow the instructions for installing Joern (https://docs.joern.io/home), then:


// In a terminal, start Joern, e.g.
joern
// import the code, e.g.
importCode("layers.c")
// Run the dataflow command
run.ossdataflow
// Save the CPG:
save

// Find paths from a "gets" source to a "system" sink
// With more recent versions of Joern, we must specify exactly which arguments
// we want data flow for:
cpg.call.name("system").argument(1).reachableByFlows(cpg.call.name("gets").argument(1)).p 

// From this point forward, I will demonstrate intermediate Joern queries
// That I will 

// Note: The getSinglePath method shown below was an early prototype. 
// You can skip it if you find the notes hard to understand.
// but I encourage you to at least run the query as shown.
// I provide more advanced versions of this function later on.

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
            val sink = cpg.method.ast.isCallTo(source).argument(tainted_index)
            sink.reachableBy(param)
        }.size > 0
    )
    try{
        val index_of_tainted_param = filteredParams.index.head
        val src = cpg.call.name(function_that_taints_param_ptr).argument.order(index_of_tainted_param)
        val sink = cpg.call.name(sink_first_arg)
        sink.reachableByFlows(src).p
    }catch{
        case x: NoSuchElementException =>{
            println("No path from " + source + "(...) to " + function_that_taints_param_ptr + "(...) found")
        }
    }
}
// Enter the function above, then try this:
getSinglePath("source_3", "gets", 1, "system") 
getSinglePath("source_4", "recv", 2, "system") 

// Moving on to another 
// Can we further rewrite the function above completely generically?
// Not only does this work for sources that taint parameter pointers,
// but it ALSO works for functions that taint returned pointers.
// Note that this yields false positives.  A more accurate version is presented much later in this document
// but this shows the general idea without the complexity required to avoid unreachable code.
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

// Enter the function above, then try this:
val mySources = ListBuffer(("gets", "n/a", 1))
val mySinks = List(("system",1))
getAllPathsv1(mySources, mySinks)
// It should return 3 results, but note that sink_3 is never called.

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
val mySources = ListBuffer(("gets", "n/a", 1))
val mySinks = List(("system",1))
getAllPaths(mySources, mySinks)

// I want to programatically find all functions that taint parameter pointers
// Pass in a List of Maps, mapping function names to tainted parameters, e.g. (gets<-List(1))
// Return a list of lists.  
// Each inner list of the return value looks like this:
// 1. Name of function that calls the source
// 2. Name of source function
// 3. Index of tainted parameter
// TODO: These examples are confusing, as the first item in the list above 
// JUST SO HAPPENS to taint the parameter WITH THE SAME INDEX as the sink that it calls!
// TODO: Also, what if a function taints multiple parameters?  It should return a List of tainted parameters!
// of function names to tainted indices, e.g. {source_3:1}
import scala.collection.mutable.ListBuffer 
import scala.util.control.Breaks._
def getFunctionsThatTaintParamPointers(sources:Map[String,List[Int]], variadicFunctions:List[String]):ListBuffer[(String, Int, String, Int)]={
    // Save results in earlyResults
    var earlyResults:ListBuffer[(String, Int, String, Int)] = ListBuffer()
    println("Hello, here's my sources", sources)
    println("Hello, here's my variadics", variadicFunctions)     

    // Iterate over each source (e.g. "gets", "recv"), then each (possibly) tainted parameter
    for ((source, taintedParams) <- sources){
        breakable{
        if(source != "main" && cpg.call.name(source).l.length==0){
            println(source+" not found, skipping.")
            break
        } 
        // Find all methods (e.g. 'source_3') that call this source (e.g. 'gets')
        def sourceCallers =  cpg.method.name(source).caller.l 
        println(sourceCallers.name.l)
        breakable{
        for(sourceCaller <- sourceCallers){
            println("Looking at "+sourceCaller.name+"->"+source)
            // I want to iterate over each parameter to each sourceCaller and determine which ones, if any, get tainted
            var maxNumberOfArguments = 1000
            if(variadicFunctions.contains(source)){
                // This is a variadic function
                // Determine the maximum number of args ever passed to this function
                maxNumberOfArguments = cpg.call.name(source).argument.l.groupBy(x => x.lineNumber).l.maxBy(x=>x._2.length)._2.length 
            }
            else{
                val calls = cpg.call.name(sourceCaller.name).l
                if(calls.length > 0){
                    maxNumberOfArguments = cpg.call.name(sourceCaller.name).head.argument.l.length
                }
                else{
                    println(sourceCaller.name + " calls " + source+ " but itself never appears to be called. skipping.")
                    break
                }

            }
            // What if this sink is known to taint multiple parameters? 
            // I don't know of any, but I should allow for the possibility
            breakable{
            for(taintedParam <- taintedParams){
                // Break out of variadic parameter analysis ASAP
                if(maxNumberOfArguments < taintedParam){
                    println("maxNumberOfArguments for "+sourceCaller.name + ":" + maxNumberOfArguments +"<" + taintedParam+"; no more args to check after")
                    break
                }
                //TODO whuch of these two approaches should I use.
                //def sink = cpg.call.name(source).argument.order(taintedParam)
                def sink = cpg.method.name(source).parameter.order(taintedParam)

                // At this point I know that sourceCaller calls a source function.
                // For each parameter to sourceCaller, which, if any, are tainted by that source?
                for(sourceCallerParameter <- Range(1, maxNumberOfArguments+1)){
                    println("Looking at "+sourceCaller.name+"("+sourceCallerParameter+")->" + source + "("+taintedParams+")")
                    //def src = cpg.call.name(sourceCaller.name).argument.order(sourceCallerParameter)
                    def src = cpg.method.name(sourceCaller.name).parameter.order(sourceCallerParameter)
                    
                    val path = sink.reachableByFlows(src).l
                    
                    if(path.length > 0){
                        println("Found taint! " +sourceCaller.name+"("+sourceCallerParameter+")->" + source + "("+taintedParams+")")
                        println("cpg.call.name(\""+source+"\").argument.order("+taintedParam+").reachableBy(cpg.call.name(\""+sourceCaller.name+"\").argument.order("+sourceCallerParameter+"))")
                        //println(sink.id.head + "==" + path.id.head+"(src.id.head: " + src.id.head+")")
                        println(path)
                        earlyResults += ((sourceCaller.name, sourceCallerParameter, source, taintedParam))
                    }
                }
            }}
        }}
    }}
    return earlyResults
}

var sources:Map[String,List[Int]] = Map()
sources += ("gets" -> List(1))
sources += ("fgets" -> List(1))
sources += ("recv" -> List(2))  
/* 
sources += ("recvfrom" -> List(2))     
sources += ("read" -> List(2))
sources += ("main" -> List(1,2))
sources += (".*fscanf" -> Range(3,10).l)
sources += (".*_sscanf" -> Range(3,10).l)
sources += (".*_scanf" -> Range(2,10).l)
*/
val variadicFunctions:List[String] = List("__isoc99_fscanf", ".*fscanf", "__isoc99_scanf", "scanf", "__isoc99_sscanf", "sscanf")
val mySources = getFunctionsThatTaintParamPointers(sources, variadicFunctions)
mySources += (("gets", 0, "n/a", 1))
val mySinks = List(("system",1))
getAllPaths(mySources, mySinks)


// Get the first argument of gets(), but only if the call to gets() is reachable from main
// By "reachable" we mean there is a path in the CPG from main() to the call.
// Note that the actual logic to execute the path may not be possible, e.g. it could still be dead code
// In English, this accesses the method "gets" in the CPG, 
// accesses all callers of "gets", filters on only those that have "main" as an ancestor.
// Of those callers of "gets", this line accesses the "gets" calls 
// (as the callers may call other functions aside from gets),
// and finally returns the first argument to each of those calls.
//
// More concisely, this line simply returns the "gets" "source" likely reachable by main,
// where "likely reachable" means a call path exists from main to "gets".
// Note: This same logic will NOT detect calls WITHIN "main".
cpg.method.name("gets").caller.filter(x => x.repeat(_.caller)(_.until(_.name("main"))).l.length>0).call.name("gets").argument.order(1).l

// This code below SHOULD find all calls to "system", including "system" calls from "main" via a second query appended to the first with "++"
val caller = "source_3"
val index = 1
val start = "main"
val sinks = cpg.method.name(caller).caller.filter(x => x.repeat(_.caller)(_.until(_.name(start))).l.length>0).call.name(caller).argument.order(index) ++ cpg.method.name(caller).caller.dedup.name(start).call.name(caller).argument.order(index) 

// Now apply the logic above to getAllPaths to only get paths "reachable" by some start point, 
// in this case I just use "main", though we could of course choose any other starting point, such as the target function of a thread:
def getAllReachablePaths(sources:ListBuffer[(String, Int, String, Int)], sinks:List[(String,Int)], start:String):ListBuffer[List[String]] = {
    val results:ListBuffer[List[String]] = ListBuffer()
    for((caller, callerIndex, source, taintedIndex) <- sources){
        for((sink, sinkIndex) <- sinks){
            print("Checking " + caller + "(" + taintedIndex + ")->" + sink+"("+sinkIndex+")\n")
            def thisSrc = cpg.method.name(caller).caller.filter(x => x.repeat(_.caller)(_.until(_.name(start))).l.length>0).call.name(caller).argument.order(taintedIndex) ++ cpg.method.name(caller).caller.dedup.name(start).call.name(caller).argument.order(taintedIndex)

            def thisSink = cpg.method.name(sink).caller.filter(x => x.repeat(_.caller)(_.until(_.name(start))).l.length>0).call.name(sink).argument.order(sinkIndex) ++ cpg.method.name(sink).caller.dedup.name(start).call.name(sink).argument.order(sinkIndex)
            
            def paths = thisSink.reachableByFlows(thisSrc).p
            if(paths.length > 0){
               results += paths
            }
        }
    }
    return results
}

def removeFalsePositives(sources:ListBuffer[(String, Int, String, Int)], sinks:List[(String,Int)], allPaths:ListBuffer[List[String]]):ListBuffer[List[String]]{
    val results:ListBuffer[List[String]] = ListBuffer()
    for(paths<-allPaths){
        for(path <- paths){
            val lines = path.split("\\n").takeRight(3)
            var source = ""
            var sink = ""
            var taintedVars = scala.collection.mutable.Set[String]()
            var sinkPoints = scala.collection.mutable.Set[String]()


            // Which sink does this path use?  It's in the last line of the results
            // What if there are multiple parameters for this sink function?
            // I'm not aware of any sinks matching this description, 
            // but as long as any of them reach the sink node that's fine.            
            for(sink, sinkIndex <-  sinks){
                if(lines.last contains source+"("){
                    var args = lines.first.split('|')(1).split(',')
                    args(0) = args(0).split(source + "\\(")(1)
                    args(args.size-1) = args.last.trim().stripSuffix(")") 

                    // Enumerate args and add the tainted one
                    // TODO I may need to sanitize/parse out the variable
                    // e.g. what if args(taintedIndex) is "my_var+5"?
                    // I can check if the arg is a member of the function by accessing the function like so:
                    // cpg.file("filename").method.lineNumberGte(X).lineNumberLte(Y)
                    // Because filename, X, and Y are all known!
                    sinkPoints += args(taintedIndex) 
                }
            }

            // Which variables are tainted from the begining?
            for(source, taintedIndex, _, _ <- sources){
                if(lines.first contains source+"("){
                    var args = lines.first.split('|')(1).split(',')
                    args(0) = args(0).split(source + "\\(")(1)
                    args(args.size-1) = args.last.trim().stripSuffix(")") 

                    // Enumerate args and add the tainted one
                    // TODO I may need to sanitize/parse out the variable
                    // e.g. what if args(taintedIndex) is "my_var+5"?
                    // I can check if the arg is a member of the function by accessing the function like so:
                    // cpg.file("filename").method.lineNumberGte(X).lineNumberLte(Y)
                    // Because filename, X, and Y are all known!
                    taintedVars += args(taintedIndex) 
                }
            }            

            /* At this point I know exactly which variables are tainted at 
            the outset, and which variable(s) need to still be tainted at 
            the end to form the desired parameter specific sink+source path.
            Next I need to trace them all the way to the sink.
            */
            for(line in linesdrop(2)){
                // Trace data dependencies
                // args is still valid from the block above

            }
        }
    )
        val thisSrc = 

    }
}

var sources:Map[String,List[Int]] = Map()
sources += ("gets" -> List(1))
sources += ("fgets" -> List(1))
sources += ("recv" -> List(2))   
/*
sources += ("recvfrom" -> List(2))     
sources += ("read" -> List(2))
sources += ("main" -> List(1,2))
sources += (".*fscanf" -> Range(3,10).l)
sources += (".*_sscanf" -> Range(3,10).l)
sources += (".*_scanf" -> Range(2,10).l)
*/
val variadicFunctions:List[String] = List("__isoc99_fscanf", ".*fscanf", "__isoc99_scanf", "scanf", "__isoc99_sscanf", "sscanf")

// TODO Use the block below for production
val mySources = getFunctionsThatTaintParamPointers(sources, variadicFunctions)
mySources += (("gets", 1, "n/a", 1))
val mySinks = List(("system",1))
val start = "main"
var allReachablePaths = getAllReachablePaths(mySources, mySinks, start)


// This block is only for testing!
val mySources = ListBuffer(("source_4", 1, "n/a", 1))
val mySinks = List(("system",1))
val start = "main"
var allReachablePaths = getAllReachablePaths(mySources, mySinks, start)
// TODO Define more sources (include argv) and sinks, e.g.

// Reference: https://blog.cys4.com/exploit/reverse-engineering/2022/04/18/From-Patch-To-Exploit_CVE-2021-35029.html
// def sink_exec = cpg.method.name(".*exec.*").callIn.argument // all the arguments
// def sink_popen = cpg.method.name("popen").callIn.argument(1) // restrict to argument 1
// def sink_system = cpg.method.name("system").callIn.argument(1) // restrict to argument 1
// sink_exec.reachableByFlows(src).map( _.elements.map( n => (n.lineNumber.get,n.astParent.code) )).l