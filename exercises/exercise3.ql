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
