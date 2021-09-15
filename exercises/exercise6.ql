import java
import semmle.code.java.security.UnsafeDeserializationQuery

from UnsafeDeserializationSink node
where
  not node.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select 
  node.asExpr().getParent().(Call).getCallee().getDeclaringType(), // deserializing class
  node.asExpr().getParent(), // deserializing method
  node.asExpr().getParent().(Call).getEnclosingCallable().getDeclaringType() // enclosing class
