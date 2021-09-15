import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import DataFlow
import PartialPathGraph

class PartialTaintConfig extends DataFlow::Configuration {
  PartialTaintConfig() { this = "PartialTaintConfig" }

  override int explorationLimit() { result = 5 }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("load") and
      ma.getMethod().getDeclaringType().hasName("Yaml") and
      sink.asExpr() = ma.getAnArgument()
    )
  }
}

from PartialPathNode n, int dist
where 
  any(PartialTaintConfig c).hasPartialFlowRev(n, _, dist) and
  n.getNode() instanceof DataFlow::ExplicitParameterNode and
  dist > 0
select dist, n.getNode().getEnclosingCallable().getDeclaringType(), n.getNode().getEnclosingCallable(), n