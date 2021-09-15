# CodeQL as an audit oracle workshop

HacktivityCon, 18th Semptember 2021

Presented by @pwntester

Slack: #??????

Documentation & tools: https://codeql.github.com

Workshop format: This is a hands-on workshop where you will be using the CodeQL Visual Studio Extension to write CodeQL.

Please feel free to ask questions at any time. If we run out of time, this is not a problem. We will just stop at an appropriate point. You can complete the remaining material in your own time if you want to. You are encouraged to experiment as you go along. Hints and solutions are provided. Where you see an arrow like this you can click to expand it:

<details>
<summary>
Hints
</summary>
Here are some hints.
</details>


# Task 0: Setup

Follow the instructions in the [README](README.md) - you want to have [this repository](https://github.com/CodeQLWorkshops/DubboWorkshop) open in Visual Studio Code. Make sure that the extension and CodeQL CLI are the latest versions.

The databases are included in the snapshot in the [databases](databases/) folder. You can also create your own databases using the CodeQL CLI.

If you already cloned the repo, `git pull` to get the latest changes.

# Exercise 1: Find the Dubbo attack surface known to CodeQL

You should get 10 results.

<details>
<summary>Hints</summary>

```
import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource source
where ...
select ...
```

</details>


<details>
<summary>Solution</summary> 

```ql
import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource source
where
  not source.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select 
  source,
  source.getEnclosingCallable().getDeclaringType(),
  source.getSourceType()
```

</details>

# Exercise 2: Model Netty sources

You should get 6 results.

<details>
<summary>Hints</summary>

A source can be added gloabally, rather than to a specific TaintTracking configuration, by extending `semmle.code.java.dataflow.FlowSources.RemoteFlowSource`: 

```ql
class NettySource extends RemoteFlowSource {
  NettySource() {
    exists(Method m |
      ...
      this.asParameter() = m.getParameter(1)
    )
  }
  override string getSourceType() { result = "Netty Source" }
}
```

The required APIs can be modelled with:

```ql
/** The ChannelInboundHandler class */
class ChannelInboundHandler extends Class {
  ChannelInboundHandler() {
    this.getASourceSupertype*().hasQualifiedName("io.netty.channel", "ChannelInboundHandler")
  }
}

/** The ChannelInboundHandlerl.channelRead method */
class ChannelReadMethod extends Method {
  ChannelReadMethod() {
      this.getName() = ["channelRead", "channelRead0", "messageReceived"] and
      this.getDeclaringType() instanceof ChannelInboundHandler
  }
}
```

and

```ql
/** The ByteToMessageDecoder class */
class ByteToMessageDecoder extends Class {
    ByteToMessageDecoder() {
      this.getASourceSupertype*().hasQualifiedName("io.netty.handler.codec", "ByteToMessageDecoder")
    }
}

/** The ByteToMessageDecoder.decode method */
class DecodeMethod extends Method {
  DecodeMethod() {
      this.getName() = ["decode", "decodeLast"] and
      this.getDeclaringType() instanceof ByteToMessageDecoder
  }
}
```

</details>

<details>
<summary>Solution</summary> 

```ql
import java
import semmle.code.java.dataflow.FlowSources

/** The ChannelInboundHandler class */
class ChannelInboundHandler extends Class {
  ChannelInboundHandler() {
    this.getASourceSupertype*().hasQualifiedName("io.netty.channel", "ChannelInboundHandler")
  }
}

/** The ChannelInboundHandlerl.channelRead method */
class ChannelReadMethod extends Method {
  ChannelReadMethod() {
      this.getName() = ["channelRead", "channelRead0", "messageReceived"] and
      this.getDeclaringType() instanceof ChannelInboundHandler
  }
}

/** The ByteToMessageDecoder class */
class ByteToMessageDecoder extends Class {
    ByteToMessageDecoder() {
      this.getASourceSupertype*().hasQualifiedName("io.netty.handler.codec", "ByteToMessageDecoder")
    }
}

/** The ByteToMessageDecoder.decode method */
class DecodeMethod extends Method {
  DecodeMethod() {
      this.getName() = ["decode", "decodeLast"] and
      this.getDeclaringType() instanceof ByteToMessageDecoder
  }
}

/** The ChannelInboundHandlerl.channelRead(1) source */
class ChannelReadSource extends RemoteFlowSource {
    ChannelReadSource() {
      exists(ChannelReadMethod m |
        this.asParameter() = m.getParameter(1)
      )
    }
    override string getSourceType() { result = "Netty Handler Source" }
}

/** The ByteToMessageDecoder.decode(1) source */
class DecodeSource extends RemoteFlowSource {
  DecodeSource() {
    exists(DecodeMethod m |
      this.asParameter() = m.getParameter(1)
    )
  }
  override string getSourceType() { result = "Netty Decoder Source" }
}

from RemoteFlowSource source
where
  (
    source instanceof ChannelReadSource or
    source instanceof DecodeSource
  ) and
  not source.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select
  source,
  source.getEnclosingCallable().getDeclaringType(),
  source.getSourceType()
```

</details>

* Explore some of the results by clicking on them
* Explore autocomplete
* Explore pop-up help
* Jump to the QL class definition
* Use the AST viewer. Right-click on any Ruby code and select "CodeQL: View AST".
* Look at query history

# Exercise 3: Variant analysis (Taint Tracking)

The `and` keyword combines two logical expressions.

You should get 8 results.

<details>
<summary>Hints</summary>

- A `TaintTracking` query boilerplate:

```ql
/**
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }

  override predicate isSource(DataFlow::Node source) {
    ...
  }

  override predicate isSink(DataFlow::Node sink) {
    ...
  }

  override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    ...
  }
}

from MyConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink
where conf.hasFlowPath(source, sink)
select sink, source, sink, "dataflow was found"
```

- The relevant APIs can be modelled with:

```ql
class DubboCodecDecodeBodyMethod extends Method {
  DubboCodecDecodeBodyMethod() {
      this.getName() = "decodeBody" and
      this.getDeclaringType().hasQualifiedName("org.apache.dubbo.rpc.protocol.dubbo", "DubboCodec")
  }
}

class ObjectInputReadMethod extends Method {
  ObjectInputReadMethod() {
      this.getName().matches("read%") and
      this.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("org.apache.dubbo.common.serialize", "ObjectInput")
  }
}

class SerializationDeserializeMethod extends Method {
  SerializationDeserializeMethod() {
      this.getName() = "deserialize" and
      this.getDeclaringType().hasQualifiedName("org.apache.dubbo.common.serialize", "Serialization")
  }
}
```

- A method call is represented with `MethodAccess` in CodeQL
- `instanceof` operator allows you to enforce CodeQL classes

</details>

<details>
<summary>Solution</summary> 

```ql
/**
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph


class DubboCodecDecodeBodyMethod extends Method {
  DubboCodecDecodeBodyMethod() {
      this.getName() = "decodeBody" and
      this.getDeclaringType().hasQualifiedName("org.apache.dubbo.rpc.protocol.dubbo", "DubboCodec")
  }
}

class ObjectInputReadMethod extends Method {
  ObjectInputReadMethod() {
      this.getName().matches("read%") and
      this.getDeclaringType()
          .getASourceSupertype*()
          .hasQualifiedName("org.apache.dubbo.common.serialize", "ObjectInput")
  }
}

class SerializationDeserializeMethod extends Method {
  SerializationDeserializeMethod() {
      this.getName() = "deserialize" and
      this.getDeclaringType().hasQualifiedName("org.apache.dubbo.common.serialize", "Serialization")
  }
}

class InsecureConfig extends TaintTracking::Configuration {
  InsecureConfig() { this = "InsecureConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DubboCodecDecodeBodyMethod m |
      m.getParameter(1) = source.asParameter()
     )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod() instanceof ObjectInputReadMethod and
      ma.getQualifier() = sink.asExpr()
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess ma |
      ma.getMethod() instanceof SerializationDeserializeMethod and
      ma.getArgument(1) = n1.asExpr() and
      ma = n2.asExpr()
    )
  }
}

from InsecureConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink
where conf.hasFlowPath(source, sink)
select sink, source, sink, "unsafe deserialization"
```

</details>

# Exercise 4: Semantic matches

This should give 14 results.

<details>
<summary>Hints</summary>

- You can model classes implementing `ObjecInput` with:

```ql
class ObjectInputClass extends RefType {
  ObjectInputClass() {
    this.getASourceSupertype*().hasQualifiedName("org.apache.dubbo.common.serialize", "ObjectInput")
  }
}
```

- Model calls to `ObjectInput.read*` method with a class
 
```ql
class ObjectInputReadCall extends MethodAccess {
  ObjectInputReadCall() {
    ..
  }
}
```

</details>

<details>
<summary>Solution</summary> 

```ql
import java

class ObjectInputClass extends RefType {
  ObjectInputClass() {
    this.getASourceSupertype*().hasQualifiedName("org.apache.dubbo.common.serialize", "ObjectInput")
  }
}

class ObjectInputReadCall extends MethodAccess {
  ObjectInputReadCall() {
    exists(Method m |
      this.getMethod() = m and
      m.getName().matches("read%") and
      m.getDeclaringType() instanceof ObjectInputClass
    )
  }
}

from ObjectInputReadCall call
where
  not call.getEnclosingCallable().getDeclaringType() instanceof ObjectInputClass and
  not call.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select 
  call,
  call.getEnclosingCallable(),
  call.getEnclosingCallable().getDeclaringType()
```

</details>

# Exercise 5: Scaling manual results

This should give 9 results.

<details>
<summary>Hints</summary>

- Exclude calls from `PojoUtils` and `JavaBeanSerializeUtil`
- The relevant APIs needed for this query are:

```ql
class PojoUtilsRealizeMethod extends Method {
  PojoUtilsRealizeMethod() {
      this.getName() = "realize" and
      this.getDeclaringType().getName() = "PojoUtils"
  }
}

class JavaBeanSerializeUtilDeserializeMethod extends Method {
  JavaBeanSerializeUtilDeserializeMethod() {
      this.getName() = "deserialize" and
      this.getDeclaringType().getName() = "JavaBeanSerializeUtil"
  }
}
```

</details>

<details>
<summary>Solution</summary>

```ql
import java

class PojoUtilsRealizeMethod extends Method {
  PojoUtilsRealizeMethod() {
      this.getName() = "realize" and
      this.getDeclaringType().getName() = "PojoUtils"
  }
}

class JavaBeanSerializeUtilDeserializeMethod extends Method {
  JavaBeanSerializeUtilDeserializeMethod() {
      this.getName() = "deserialize" and
      this.getDeclaringType().getName() = "JavaBeanSerializeUtil"
  }
}

from MethodAccess ma
where
  (
    ma.getMethod() instanceof PojoUtilsRealizeMethod or 
    ma.getMethod() instanceof JavaBeanSerializeUtilDeserializeMethod
  ) and
  not ma.getEnclosingCallable().getDeclaringType() = ma.getMethod().getDeclaringType() and
  not ma.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select ma, ma.getEnclosingCallable().getDeclaringType()
```

</details>

## Exercise 6: Semantic sinks heatmap  

This should give 23 results.

<details>
<summary>Hints</summary>

- Reuse `UnsafeDeserializationSink` from `semmle.code.java.security.UnsafeDeserializationQuery`:

```ql
import java
import semmle.code.java.security.UnsafeDeserializationQuery

from UnsafeDeserializationSink node
where ...
select ...
```

</details>


<details>
<summary>Solution</summary> 

```ql
import java
import semmle.code.java.security.UnsafeDeserializationQuery

from UnsafeDeserializationSink node
where
  not node.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select 
  node.asExpr().getParent().(Call).getCallee().getDeclaringType(), // deserializing class
  node.asExpr().getParent(), // deserializing method
  node.asExpr().getParent().(Call).getEnclosingCallable().getDeclaringType() // enclosing class
```

</details>

# Exercise 7: Configuration Centers

There should be 10 results.

<details>
<summary>Hints</summary>

- The relevant APIs for this query are:
 
```ql
class NotifyListener extends RefType {
  NotifyListener() {
    this.hasQualifiedName("org.apache.dubbo.registry", "NotifyListener")
  }
}

class ConfigurationListener extends RefType {
  ConfigurationListener() {
    this.hasQualifiedName("org.apache.dubbo.common.config.configcenter", "ConfigurationListener")
  }
}

class ConfigurationListenerProcessMethod extends Method {
  ConfigurationListenerProcessMethod() {
    this.getName() = "process" and
    this.getDeclaringType().getASupertype*() instanceof ConfigurationListener
  }
}

class NotifyListenerNotifyMethod extends Method {
  NotifyListenerNotifyMethod() {
    this.getName() = "notify" and
    this.getDeclaringType().getASupertype*() instanceof NotifyListener 
  }
}
```

</details>

<details>
<summary>Solution</summary>

```ql
import java
import semmle.code.java.dataflow.FlowSources

class NotifyListener extends RefType {
  NotifyListener() {
    this.hasQualifiedName("org.apache.dubbo.registry", "NotifyListener")
  }
}

class ConfigurationListener extends RefType {
  ConfigurationListener() {
    this.hasQualifiedName("org.apache.dubbo.common.config.configcenter", "ConfigurationListener")
  }
}

class ConfigurationListenerProcessMethod extends Method {
  ConfigurationListenerProcessMethod() {
    this.getName() = "process" and
    this.getDeclaringType().getASupertype*() instanceof ConfigurationListener
  }
}

class NotifyListenerNotifyMethod extends Method {
  NotifyListenerNotifyMethod() {
    this.getName() = "notify" and
    this.getDeclaringType().getASupertype*() instanceof NotifyListener 
  }
}

class DubboListener extends RemoteFlowSource {
  DubboListener() {
    (exists(NotifyListenerNotifyMethod m |
        this.asParameter() = m.getAParameter()
      ) or
      exists(ConfigurationListenerProcessMethod m |
        this.asParameter() = m.getAParameter() 
      )) and
      not this.getLocation().getFile().getRelativePath().matches("%/src/test/%")
  }
  override string getSourceType() { result = "Dubbo Listener Source" }
}
  
from DubboListener l
select 
  l,
  l.asParameter().getCallable(),
  l.asParameter().getCallable().getDeclaringType()
```

</details>

## Exercise 8: Script Injection

There should be 2 results.

<details>
<summary>Hints</summary>

- Reuse the [experimental Script injection](https://github.com/github/codeql/blob/main/java/ql/src/experimental/Security/CWE/CWE-094/ScriptInjection.ql)
- Add sources from step 7
- import local `models.qll` file to bring some unmerged library taint steps
- Add a new TaintStep for `URL`:
```ql
class URLTaintStep extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
        exists(MethodAccess ma |
            ma.getMethod().getName().matches("get%") and
            ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.dubbo.common", "URL") and
            n1.asExpr() = ma.getQualifier() and
            n2.asExpr() = ma
        )
    }
}
```

</details>

<details>
<summary>Solution</summary>

```ql
/**
 * @name Injection in Java Script Engine
 * @description Evaluation of user-controlled data using the Java Script Engine may
 *              lead to remote code execution.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/unsafe-eval
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph
import models
import dubbo

/** A method of ScriptEngine that allows code injection. */
class ScriptEngineMethod extends Method {
  ScriptEngineMethod() {
    this.getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine") and
    this.hasName("eval")
    or
    this.getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "Compilable") and
    this.hasName("compile")
    or
    this.getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngineFactory") and
    this.hasName(["getProgram", "getMethodCallSyntax"])
  }
}

/** The context class `org.mozilla.javascript.Context` of Rhino Java Script Engine. */
class RhinoContext extends RefType {
  RhinoContext() { this.hasQualifiedName("org.mozilla.javascript", "Context") }
}

/** A method that evaluates a Rhino expression with `org.mozilla.javascript.Context`. */
class RhinoEvaluateExpressionMethod extends Method {
  RhinoEvaluateExpressionMethod() {
    this.getDeclaringType().getAnAncestor*() instanceof RhinoContext and
    this.hasName([
        "evaluateString", "evaluateReader", "compileFunction", "compileReader", "compileString"
      ])
  }
}

/**
 * A method that compiles a Rhino expression with
 * `org.mozilla.javascript.optimizer.ClassCompiler`.
 */
class RhinoCompileClassMethod extends Method {
  RhinoCompileClassMethod() {
    this.getDeclaringType()
        .getASupertype*()
        .hasQualifiedName("org.mozilla.javascript.optimizer", "ClassCompiler") and
    this.hasName("compileToClassFiles")
  }
}

/**
 * A method that defines a Java class from a Rhino expression with
 * `org.mozilla.javascript.GeneratedClassLoader`.
 */
class RhinoDefineClassMethod extends Method {
  RhinoDefineClassMethod() {
    this.getDeclaringType()
        .getASupertype*()
        .hasQualifiedName("org.mozilla.javascript", "GeneratedClassLoader") and
    this.hasName("defineClass")
  }
}

/**
 * Holds if `ma` is a call to a `ScriptEngineMethod` and `sink` is an argument that
 * will be executed.
 */
predicate isScriptArgument(MethodAccess ma, Expr sink) {
  exists(ScriptEngineMethod m |
    m = ma.getMethod() and
    if m.getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngineFactory")
    then sink = ma.getArgument(_) // all arguments allow script injection
    else sink = ma.getArgument(0)
  )
}

/**
 * Holds if a Rhino expression evaluation method is vulnerable to code injection.
 */
predicate evaluatesRhinoExpression(MethodAccess ma, Expr sink) {
  exists(RhinoEvaluateExpressionMethod m | m = ma.getMethod() |
    (
      if ma.getMethod().getName() = "compileReader"
      then sink = ma.getArgument(0) // The first argument is the input reader
      else sink = ma.getArgument(1) // The second argument is the JavaScript or Java input
    ) and
    not exists(MethodAccess ca |
      ca.getMethod().hasName(["initSafeStandardObjects", "setClassShutter"]) and // safe mode or `ClassShutter` constraint is enforced
      ma.getQualifier() = ca.getQualifier().(VarAccess).getVariable().getAnAccess()
    )
  )
}

/**
 * Holds if a Rhino expression compilation method is vulnerable to code injection.
 */
predicate compilesScript(MethodAccess ma, Expr sink) {
  exists(RhinoCompileClassMethod m | m = ma.getMethod() | sink = ma.getArgument(0))
}

/**
 * Holds if a Rhino class loading method is vulnerable to code injection.
 */
predicate definesRhinoClass(MethodAccess ma, Expr sink) {
  exists(RhinoDefineClassMethod m | m = ma.getMethod() | sink = ma.getArgument(1))
}

/** A script injection sink. */
class ScriptInjectionSink extends DataFlow::ExprNode {
  MethodAccess methodAccess;

  ScriptInjectionSink() {
    isScriptArgument(methodAccess, this.getExpr()) or
    evaluatesRhinoExpression(methodAccess, this.getExpr()) or
    compilesScript(methodAccess, this.getExpr()) or
    definesRhinoClass(methodAccess, this.getExpr())
  }

  /** An access to the method associated with this sink. */
  MethodAccess getMethodAccess() { result = methodAccess }
}

/**
 * A taint tracking configuration that tracks flow from `RemoteFlowSource` to an argument
 * of a method call that executes injected script.
 */
class ScriptInjectionConfiguration extends TaintTracking::Configuration {
  ScriptInjectionConfiguration() { this = "ScriptInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
   }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ScriptInjectionSink
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, ScriptInjectionConfiguration conf
where conf.hasFlowPath(source, sink)
select sink.getNode().(ScriptInjectionSink).getMethodAccess(), source, sink,
  "Java Script Engine evaluate $@.", source.getNode(), "user input"
```

</details>

# Next steps

* For tools and documentation, visit https://codeql.github.com
* Slack: ghsecuritylab.slack.com
* Enable CodeQL analysis for your own repos
