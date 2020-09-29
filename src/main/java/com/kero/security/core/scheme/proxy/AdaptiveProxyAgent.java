package com.kero.security.core.scheme.proxy;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.ClassAccessScheme;
import com.kero.security.core.utils.ByteBuddyClassUtils;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;

public class AdaptiveProxyAgent extends ProxyAgentBaseCached {
	
	public AdaptiveProxyAgent(ClassAccessScheme scheme) {
		super(scheme);

	}

	@Override
	protected Class<? extends AccessProxy> createProxyClass() throws Exception {

		Class<?> superType = determineProxySuperclass();
		List<Class<?>> interfaces = collectProxyInterfaces(superType);
		
		return (Class<? extends AccessProxy>) new ByteBuddy()
			.subclass(superType)
			.implement(interfaces)
			.defineField("original", Object.class, Visibility.PRIVATE)
			.defineField("pac", PreparedAccessConfiguration.class, Visibility.PRIVATE)
			.defineConstructor(Visibility.PUBLIC)
			.withParameters(Object.class, PreparedAccessConfiguration.class)
			.intercept(MethodCall.invoke(superType.getDeclaredConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1))))
			.method(ElementMatchers.isPublic())
			.intercept(InvocationHandlerAdapter.of(this.scheme))
			.defineMethod("getOriginal", Object.class, Visibility.PUBLIC).intercept(FieldAccessor.ofField("original"))
			.defineMethod("getConfiguration", PreparedAccessConfiguration.class, Visibility.PUBLIC).intercept(FieldAccessor.ofField("pac"))
			.make()
			.load(this.scheme.getAgent().getClassLoader())
			.getLoaded();
	}
	
	private List<Class<?>> collectProxyInterfaces(Class<?> superClazz) {
		
		List<Class<?>> interfaces = new ArrayList<>();
			interfaces.add(AccessProxy.class);
		
			Class<?> currentClass = this.scheme.getTypeClass();
			
			while(currentClass != superClazz) {
				
				for(Class<?> inter : currentClass.getInterfaces()) {
					
					interfaces.add(inter);
				}
				
				currentClass = currentClass.getSuperclass();
			}
		
		return interfaces;
	}
	
	private Class<?> determineProxySuperclass() {
		
		Class<?> superType = this.scheme.getTypeClass().getSuperclass();
		
		while(superType != Object.class) {
			
			boolean superAccessible = ByteBuddyClassUtils.checkAccessible(superType);
			
			if(!Modifier.isFinal(superType.getModifiers()) && superAccessible) {
				
				break;
			}
			
			superType = superType.getSuperclass();
		}
		
		return superType;
	}

	public static AdaptiveProxyAgent create(ClassAccessScheme scheme) { 
		
		return new AdaptiveProxyAgent(scheme);
	}
}
