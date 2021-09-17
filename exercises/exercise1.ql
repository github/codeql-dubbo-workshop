import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource source
where
  not source.getLocation().getFile().getRelativePath().matches("%/src/test/%")
select 
  source,
  source.getEnclosingCallable().getDeclaringType(),
  source.getLocation().getFile().getBaseName(),
  source.getSourceType()