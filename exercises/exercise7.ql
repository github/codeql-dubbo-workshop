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


