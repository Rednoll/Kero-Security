package com.kero.security.core.scheme.proxy;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.ClassAccessScheme;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;

public class SubclassProxyAgent extends ProxyAgentBaseCached {

	public SubclassProxyAgent(ClassAccessScheme scheme) {
		super(scheme);
	
	}
	
	@Override
	protected Class<? extends AccessProxy> createProxyClass() throws Exception {

		boolean hasDefaultConstructor = true;
		
		Class<?> typeClass = this.scheme.getTypeClass();
		
		try {
			
			this.scheme.getTypeClass().getDeclaredConstructor();
		}
		catch(NoSuchMethodException e) {
			
			hasDefaultConstructor = false;
		}
		
		return (Class<? extends AccessProxy>) new ByteBuddy()
			.subclass(typeClass)
			.implement(AccessProxy.class)
			.defineField("original", Object.class, Visibility.PRIVATE)
			.defineField("pac", PreparedAccessConfiguration.class, Visibility.PRIVATE)
			.defineConstructor(Visibility.PUBLIC)
			.withParameters(Object.class, PreparedAccessConfiguration.class)
			.intercept(hasDefaultConstructor
				? MethodCall.invoke(typeClass.getDeclaredConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1)))
				: FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1)))
			.method(ElementMatchers.isPublic())
			.intercept(InvocationHandlerAdapter.of(this.scheme))
			.defineMethod("getOriginal", Object.class, Visibility.PUBLIC).intercept(FieldAccessor.ofField("original"))
			.defineMethod("getConfiguration", PreparedAccessConfiguration.class, Visibility.PUBLIC).intercept(FieldAccessor.ofField("pac"))
			.make()
			.load(this.scheme.getAgent().getClassLoader())
			.getLoaded();
	}
	
	public static SubclassProxyAgent create(ClassAccessScheme scheme) { 
		
		return new SubclassProxyAgent(scheme);
	}
}
