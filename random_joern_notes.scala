// I learned to combine queries from this resource:
// https://snoopysecurity.github.io/software-security/2021/12/08/joern-cheat-sheet.html

// Combine query results: Get a sorted, deduplciated list of local var AND parameter names for some function:
val func_name = "main"
(cpg.method.name(func_name).local ++ cpg.method.name(func_name).parameter).name.l.dedup.sorted 
// Save as a traversal
def func_params_and_locals = (cpg.method.name(func_name).local ++ cpg.method.name(func_name).parameter).name.l.dedup.sorted 

// Assuming there's only one call to fscanf, get the number of arguments to fscanf in that call:
cpg.method.name(".*fscanf").caller.call.name(".*fscanf").argument.l.length

// Get the maximum number of arguments ever provided to a variadic function
val x = cpg.call.name(".*printf").argument.l.groupBy(x => x.lineNumber).l.maxBy(x=>x._2.length)._2.length

// Find arguments that are tainted by "gets"
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

// Learning point: These two expressions are equivalent.  
// Not very useful, except to know that it's possible to create unnecessarily convoluted queries.
cpg.call.name("system").astChildren.isExpression.astParent.l
cpg.call.name("system").l

// Turns out Joern can't track data flow between function arguments, as these options all yield false positives:
def src = cpg.call.name("source_3").argument.order(2)
def sink = cpg.call.name("recv").argument.order(2) 
sink.reachableBy(src)

def src = cpg.call.name("source_4").argument.order(2)
def sink = cpg.call.name("recv").argument.order(2) 
sink.reachableBy(src).p

def src = cpg.call.name("source_4").argument.order(1)
def sink = cpg.call.name("recv").argument.order(2) 
sink.reachableBy(src).p

def src = cpg.call.name("source_4").argument.order(2)
def sink = cpg.call.name("recv").argument.order(2) 
sink.reachableByFlows(src).p

def src = cpg.call.name("source_4").argument.order(1)
def sink = cpg.call.name("recv").argument.order(2) 
sink.reachableByFlows(src).p

def src = cpg.method.name("source_4").parameter.order(1)
def sink = cpg.method.name("recv").parameter.order(2) 
sink.reachableBy(src).p

def src = cpg.method.name("source_4").parameter.order(2)
def sink = cpg.method.name("recv").parameter.order(2) 
sink.reachableBy(src).p

def src = cpg.method.name("source_4").parameter.order(1)
def sink = cpg.method.name("recv").parameter.order(2) 
sink.reachableByFlows(src).p

def src = cpg.method.name("source_4").parameter.order(2)
def sink = cpg.method.name("recv").parameter.order(2) 
sink.reachableByFlows(src).p