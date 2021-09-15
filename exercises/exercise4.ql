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