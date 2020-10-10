package com.kero.security.core.proxy;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.scheme.AccessProxy;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;

public class SubclassProxyWrapper extends ProxyWrapperBase {

	public SubclassProxyWrapper(Class<?> targetClass) {
		super(targetClass);
		
	}

	@Override
	public Class<?> createProxyClass() {

		boolean hasDefaultConstructor = true;
	
		try {
			
			targetClass.getDeclaredConstructor();
		}
		catch(NoSuchMethodException e) {
			
			hasDefaultConstructor = false;
		}
		
		try {
			
			return new ByteBuddy()
				.subclass(this.targetClass)
				.implement(AccessProxy.class)
				.defineField("original", Object.class, Visibility.PRIVATE)
				.defineField("pac", PreparedAccessConfiguration.class, Visibility.PRIVATE)
				.defineConstructor(Visibility.PUBLIC)
				.withParameters(Object.class, PreparedAccessConfiguration.class)
				.intercept(hasDefaultConstructor
					? MethodCall.invoke(targetClass.getDeclaredConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1)))
					: FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1)))
				.method(ElementMatchers.isPublic())
				.intercept(InvocationHandlerAdapter.toField("pac"))
				.defineMethod("getOriginal", Object.class, Visibility.PUBLIC).intercept(FieldAccessor.ofField("original"))
				.make()
				.load(ClassLoader.getSystemClassLoader())
				.getLoaded();
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
}
