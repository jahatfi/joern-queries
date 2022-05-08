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

//TODO Find tainted pointers
// First, find arguments that are tainted,
// TODO, find the variables they correspond to in the caller
cpg.call.name("gets").argument.order(1).isArgument

// Find the first path in layers.c
// The line below creates a query to find all arguments passed TO gets
val src = cpg.call.name("gets")
// The line below creates a query to find all aruments passed TO system
val sink = cpg.call.name("system")
// Are any sinks reachable by sources?
sink.reachableByFlows(src).p

// Find the second path in layers.c
// The line below creates a query to find all the first arguments passed TO source_3
def src = cpg.call.name("source_3").argument.order(1).isArgument
// The line below creates a query to find all aruments passed TO system
def sink = cpg.call.name("system")
// Are any sinks reachable by sources?
sink.reachableByFlows(src).p

// Rewrite the above more generically:

// Enter the function below, then try this:
// getPath2("source_3", "gets", "system") 
// Only the first arg requires more analysis to find.
// The other two are well known from the language
def getPath2(   function_that_taints_param_ptr:String, 
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

// I want to programatically find all functions that taint parameter pointers
// TODO Pass in a dictionary of function names (e.g. {gets:0} to tainted indices
// TODO Return a dictionary of function names to tainted indices, e.g. {source_3:0}
def getFunctionsThatTaintParamPointers:overflowdb.traversal.Traversal[io.shiftleft.codepropertygraph.generated.nodes.Method] = {
    println("Hello")
    val taintFirstIndex = "gets"
    def candidateMethods = {cpg.method.name(taintFirstIndex).caller}
    def filteredMethods = {candidateMethods.filter(
        method => {
            val sink = cpg.method.ast.isCallTo(taintFirstIndex).argument(1)
            sink.reachableBy(method.parameter)        
        }.size > 0
    )}.l
    def taintedIndices{
        //Iterate over all args to this function,
        // checking which one(s) are tainted
        filteredMethods.foreach{
            cpg.call.name(taintFirstIndex).head.argument.filter{
                argument => {
                    val src = cpg.method.ast.isCallTo(taintFirstIndex).argument(1)
                    src.reachableBy(argument)        
                }.size > 0            
            }.l
        }
    }
    return taintedIndices
}

getPath2(getFunctionsThatTaintParamPointers, "gets", "system") +

val sources = Map("recv" -> 1) //"gets" -> 0, 
// I want to programatically find all functions that taint parameter pointers
// TODO Pass in a dictionary of function names (e.g. {gets:0} to tainted indices
// TODO Return a dictionary of function names to tainted indices, e.g. {source_3:0}
def getFunctionsThatTaintParamPointers(sourceDict: Map[String, Int]):String = { //overflowdb.traversal.Traversal[io.shiftleft.codepropertygraph.generated.nodes.Method] = {
    val desiredMethods = List()
    def candidateMethods = {
        for ((source,taintedIndex) <- sourceDict){
            println("Source: "+source)
            def candidateMethods = {cpg.method.name(source).caller}
            def filteredMethods = {candidateMethods.filter(
                method => {
                    val sink = cpg.method.ast.isCallTo(source).argument(taintedIndex)
                    sink.reachableBy(method.parameter)        
                }.size > 0  
            ).name.head}
            desiredMethods :+ filteredMethods
        }   
    }
    println(desiredMethods)
    return desiredMethods
}
getFunctionsThatTaintParamPointers(sources)
getPath2(getFunctionsThatTaintParamPointers, "gets", "system") 

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