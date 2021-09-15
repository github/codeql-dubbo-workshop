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
      this.getDeclaringType().getName() =  "JavaBeanSerializeUtil"
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