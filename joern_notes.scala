// References: 
//https://jaiverma.github.io/blog/joern-uboot
//https://jaiverma.github.io/blog/joern-intro
//https://snoopysecurity.github.io/software-security/2021/12/08/joern-cheat-sheet.html


cpg.call.name("system").astChildren.isExpression.astParent.l

// Start here:
run.ossdataflow

// Combine query results: Get all local vars and parameters 
(cpg.method.name("main").local ++ cpg.method.name("main").parameter).l

//https://snoopysecurity.github.io/software-security/2021/12/08/joern-cheat-sheet.html
// Also 
def source = cpg.method.name(".*alloc.*").parameter  cpg.method.fullName("main").parameter

// Assuming there's only one call to fscanf, get the number of arguments to fscanf in that call:
cpg.method.name(".*fscanf").caller.call.name(".*fscanf").argument.l.length

// Get the maximum number of arguments ever provided to a variadic function
val x = cpg.call.name(".*printf").argument.l.groupBy(x => x.lineNumber).l.maxBy(x=>x._2.length)._2.length

//TODO Find tainted pointers
// First, find arguments that are tainted,
// TODO, find the variables they correspond to in the caller
cpg.call.name("gets").argument.order(1).isArgument

// Find the first path in layers.c
// The line below creates a query to find all arguments passed TO gets
def src = cpg.call.name("gets")
// The line below creates a query to find all aruments passed TO system
def sink = cpg.call.name("system")
// Are any sinks reachable by sources?
sink.reachableByFlows(src).p
cpg.call.name("system").reachableByFlows(cpg.call.name("gets"))

// Find the second path in layers.c
// The line below creates a query to find all the first arguments passed TO source_3
def src = cpg.call.name("source_3").argument.order(1).isArgument
// The line below creates a query to find all aruments passed TO system
def sink = cpg.call.name("system")
// Are any sinks reachable by sources?
sink.reachableByFlows(src).p

// Rewrite the above more generically:

// Only the first arg requires more analysis to find.
// The other two are well known from the language
def getSinglePath(function_that_taints_param_ptr:String, 
            source_that_taints_first_arg:String,
            sink_first_arg:String) = {
    //val function_that_taints_param_ptr = "source_3"
    val src3_params = cpg.method.name(function_that_taints_param_ptr).parameter
    val filteredParams = src3_params.filter(
        param => {
            //val src = method.parameter
            val sink = cpg.method.ast.isCallTo(source_that_taints_first_arg).argument(1)
            sink.reachableBy(param)
        }.size > 0
    )

    val index_of_tainted_param = filteredParams.index.head

    val src = cpg.call.name(function_that_taints_param_ptr).argument.order(index_of_tainted_param)

    //val src = cpg.call.name("gets")
    //val sink = cpg.call.name("system")
    val sink = cpg.call.name(sink_first_arg)
    sink.reachableByFlows(src).p
}
// Enter the function above, then try this:
getSinglePath("source_3", "gets", "system") 

// Can we further rewrite the function above completely generically?
// Not only does this work for sources that taint parameter pointers,
// but it ALSO works for functions that tainted returned pointers
// Note that this yields false positives.  A more accurate version is presented much later in this document
// but this shows the general idea without the complexity required to avoid unreachable code.
def getAllPathsv1(sources:ListBuffer[(String, String, Int)], sinks:List[(String,Int)]):ListBuffer[List[String]] = {
    val results:ListBuffer[List[String]] = ListBuffer()
    for((caller, source, tainted_index) <- sources){
        for((sink, sink_index) <- sinks){
            print("Checking " + caller + "(" + tainted_index + ")->" + sink+"("+sink_index+")\n")
            // TODO: Fix the fact that this is getting unreachable code :(
            val this_src = cpg.call.name(caller).argument.order(tainted_index)
            val this_sink = cpg.call.name(sink).l.argument.order(sink_index)
            val paths = this_sink.reachableByFlows(this_src).p
            println(paths)
            if(paths.length > 0){
                results += paths
            }
        }
    }
    return results
}

import scala.collection.mutable.ListBuffer 
def getAllPaths(sources:ListBuffer[(String, String, Int)], sinks:List[(String,Int)]):ListBuffer[String] = {
    val results:ListBuffer[List[String]] = ListBuffer()
    for((caller, source, tainted_index) <- sources){
        for((sink, sink_index) <- sinks){
            print("Checking " + caller + "(" + tainted_index + ")->" + sink+"("+sink_index+")\n")
            // Ideally we'd only need the 3 lines below to trace any path from any source 
            // to any sink.  This code takes into account the exact parameters that are tainted (my contribution), 
            // including return values (native to Joern.)
            // That siad, it yields results with both duplicate lines AND unreachable code.
            // E.g. When analyzing layers.c,  it yields sink_3() as a
            // complete source->sink path, yet sink_3 is never called from anywhere!
            def this_src = cpg.call.name(caller).argument.order(tainted_index)
            def this_sink = cpg.call.name(sink).l.argument.order(sink_index)
            def paths = this_sink.reachableByFlows(this_src).p

            // This whole mess below is designed to exclude unreachable code.
            // The code below does not trace flow paths by specific arguments,
            // so in that way it's less complete (more false positives related to 
            // tracing arguments that might not be accurate), yet at the same time 
            // I found this same approach to avoid dead code (more sound) more so 
            // than the approach above.
            print("Checking flow to any args: any args: " + caller + "(...)->" + sink+"(...)\n")
            def paths2 = cpg.call.name(sink).reachableByFlows(cpg.call.name(caller)).p

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
                    val dedup_paths2:ListBuffer[String] = ListBuffer()
                    for(path2 <- paths2){
                        for(line <- path2.split("\\n")){
                            if(!dedup_paths2.contains(line.trim() + "\n")){
                                dedup_paths2 += line.trim() + "\n"
                            }
                        }                        
                    }                        
                    for(path <- paths){
                        val dedup_paths:ListBuffer[String] = ListBuffer()
                        for(line <- path.split("\\n")){
                            if(!dedup_paths.contains(line.trim() + "\n")){
                                dedup_paths += line.trim() + "\n"
                            }
                        }
                        // This path in paths has been deduplicated (duplicates removed)
                        // If the same path exists in paths2 (also deduplicated), I am 
                        // more confident that this path is NOT a false positive.
                        // Save it to the results
                        val new_paths = (dedup_paths intersect dedup_paths2)
                        results += new_paths.l                 
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
val my_sources = ListBuffer(("gets", "n/a", 1))
val my_sinks = List(("system",1))
getAllPaths(my_sources, my_sinks)

// I want to programatically find all functions that taint parameter pointers
// DONE (ish) Pass in a dictionary of function names (e.g. {gets:0} to tainted indices
// DONE Return a dictionary of function names to tainted indices, e.g. {source_3:0}
import scala.collection.mutable.ListBuffer 
import scala.util.control.Breaks._
def getFunctionsThatTaintParamPointers:ListBuffer[(String, String, Int)]={//Map[String,List[Int]]={//overflowdb.traversal.Traversal[io.shiftleft.codepropertygraph.generated.nodes.Method] = {
    var sources:Map[String,List[Int]] = Map()
    sources += ("gets" -> List(1))
    sources += ("fgets" -> List(1))
    sources += ("recv" -> List(2))   
    sources += ("recvfrom" -> List(2))     
    sources += ("read" -> List(2))
    sources += ("main" -> List(1,2))
    val variadicFunctions:List[String] = List("__isoc99_fscanf", ".*fscanf", "__isoc99_scanf", "scanf", "__isoc99_sscanf", "sscanf")

    sources += (".*fscanf" -> Range(3,10).l)
    sources += (".*_sscanf" -> Range(3,10).l)
    sources += (".*_scanf" -> Range(2,10).l)

    println("Hello, here's my sources", sources)
    println("Hello, here's my variadics", variadicFunctions)

    // Save results in earlyResults
    var earlyResults:ListBuffer[(String, String, Int)] = ListBuffer()
     
    // Iterate over each source, then each (possibly) tainted parameter
    for ((source, tainted_params) <- sources){
        breakable{
            if(source != "main" && cpg.call.name(source).l.length==0){
                println(source+" not found, skipping.")
                break
            } 
            def candidateMethods = {cpg.method.name(source).caller}  
            var maxNumberOfArguments = 1000
            if(variadicFunctions.contains(source)){
                maxNumberOfArguments = cpg.call.name(source).argument.l.groupBy(x => x.lineNumber).l.maxBy(x=>x._2.length)._2.length 
            }
            
            // Iterate over each (possibly) tainted parameter
            breakable{
                for (tainted_param <- tainted_params){
                    if(maxNumberOfArguments < tainted_param){
                        println("Was about to examine variadic source: " + source +" but no more args to check after #" + tainted_param)
                        break
                    }

                    println("Looking at source " + source + ", tainted param #"+ tainted_param)

                    // E.g. "gets", 1
                    def filteredMethods = {candidateMethods.filter(
                        method => {
                            val sink = cpg.method.ast.isCallTo(source).argument(tainted_param)
                            sink.reachableBy(method.parameter)        
                        }.size > 0
                    )}.name    
                    var r = filteredMethods.l
                    if(r.length >= 1){
                        println("Filtered method is " + r)
                        earlyResults += ((filteredMethods.head, source, tainted_param))
                    }
                }
            }
        }
    }
    return earlyResults
}

getFunctionsThatTaintParamPointers
//val my_sources = getSinglePath(getFunctionsThatTaintParamPointers.head._1, "gets", "system") 
val my_sources = getFunctionsThatTaintParamPointers
my_sources += (("gets", "n/a", 1))
val my_sinks = List(("system",1))
getAllPaths(my_sources, my_sinks)



// This scala method will find functions that 
// receive an argument affected by gets() and 
// pass that argument to system()
// Therefore main() is excluded, as Joern is examining
// the parameters passed in (e.g. argv, argc)
def getFlow() = {
    val methods = cpg.method.name("system").caller
    val filteredMethods = methods.filter(
        method => {
            val src = method.parameter
            val sink = method.ast.isCallTo("system").argument(1)
            sink.reachableBy(src)
        }.size > 0
    )

    val src = cpg.call.name("gets")
    val sink = filteredMethods.parameter.argument
    sink.reachableByFlows(src).p
}

// This scala method will find functions that 
// receive an argument affected by gets() and 
// pass that argument to system()
// Therefore main() is excluded, as Joern is examining
// the parameters passed in (e.g. argv, argc)
def getFlow2() = {
    val sink_parent_methods = cpg.method.name("system").caller
    val filteredSinkPMethods = sink_parent_methods.filter(
        method => {
            val tainted_buff_ptr = cpg.call.name("gets").argument.order(1)
            val sink = method.ast.isCallTo("system").argument(1)
            sink.reachableBy(tainted_buff_ptr)
        }.size > 0
    )

    val src_parent_methods = cpg.method.name("gets").caller
    val filteredSrcPMethods = src_parent_methods.filter(
        method => {
            val tainted_buff_ptr = method.call.name("gets").argument.order(1).isParameter
            val sink = cpg.call.name("system").argument(1)
            sink.reachableBy(tainted_buff_ptr)
        }.size > 0
    )    

    //val src = cpg.call.name("gets")
    //val src = cpg.method.name("gets").caller
    //val sink = filteredMethods.parameter ++ filteredMethods.local
    //val sink = filteredMethods.local

    filteredSinkPMethods.reachableByFlows(filteredSrcPMethods).p
}

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
def getAllReachablePaths(sources:ListBuffer[(String, String, Int)], sinks:List[(String,Int)], start:String):ListBuffer[List[String]] = {
    val results:ListBuffer[List[String]] = ListBuffer()
    for((caller, source, tainted_index) <- sources){
        for((sink, sink_index) <- sinks){
            print("Checking " + caller + "(" + tainted_index + ")->" + sink+"("+sink_index+")\n")
            def this_src = cpg.method.name(caller).caller.filter(x => x.repeat(_.caller)(_.until(_.name(start))).l.length>0).call.name(caller).argument.order(tainted_index) ++ cpg.method.name(caller).caller.dedup.name(start).call.name(caller).argument.order(tainted_index)

            def this_sink = cpg.method.name(sink).caller.filter(x => x.repeat(_.caller)(_.until(_.name(start))).l.length>0).call.name(sink).argument.order(sink_index) ++ cpg.method.name(sink).caller.dedup.name(start).call.name(sink).argument.order(sink_index)
            
            def paths = this_sink.reachableByFlows(this_src).p
            if(paths.length > 0){
               results += paths
            }
        }
    }
    return results
}

val my_sources = getFunctionsThatTaintParamPointers
my_sources += (("gets", "n/a", 1))
val my_sinks = List(("system",1))
val start = "main"
getAllReachablePaths(my_sources, my_sinks, start)

// TODO Define more sources (include argv) and sinks, e.g.

// https://blog.cys4.com/exploit/reverse-engineering/2022/04/18/From-Patch-To-Exploit_CVE-2021-35029.html
// def sink_exec = cpg.method.name(".*exec.*").callIn.argument // all the arguments
// def sink_popen = cpg.method.name("popen").callIn.argument(1) // restrict to argument 1
// def sink_system = cpg.method.name("system").callIn.argument(1) // restrict to argument 1
// sink_exec.reachableByFlows(src).map( _.elements.map( n => (n.lineNumber.get,n.astParent.code) )).l