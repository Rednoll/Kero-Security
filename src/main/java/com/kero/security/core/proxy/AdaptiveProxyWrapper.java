package com.kero.security.core.proxy;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.utils.ByteBuddyClassUtils;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;

public class AdaptiveProxyWrapper extends ProxyWrapperBase {

	public AdaptiveProxyWrapper(Class<?> targetClass) {
		super(targetClass);
		
	}

	@Override
	protected Class<?> createProxyClass() {
		
		Class<?> superType = determineProxySuperclass();
		List<Class<?>> interfaces = collectProxyInterfaces(superType);
		
		boolean hasDefaultConstructor = true;
		
		try {
			
			superType.getDeclaredConstructor();
		}
		catch(NoSuchMethodException e) {
			
			hasDefaultConstructor = false;
		}
		
		try {
			
			return new ByteBuddy()
				.subclass(superType)
				.implement(interfaces)
				.defineField("original", Object.class, Visibility.PRIVATE)
				.defineField("pac", PreparedAccessConfiguration.class, Visibility.PRIVATE)
				.defineConstructor(Visibility.PUBLIC)
				.withParameters(Object.class, PreparedAccessConfiguration.class)
				.intercept(hasDefaultConstructor
						? MethodCall.invoke(superType.getDeclaredConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1)))
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
	
	private List<Class<?>> collectProxyInterfaces(Class<?> superClazz) {
		
		Set<Class<?>> interfaces = new HashSet<>();
			interfaces.add(AccessProxy.class);
		
			Class<?> currentClass = this.targetClass;
			
			while(currentClass != superClazz) {
				
				for(Class<?> inter : currentClass.getInterfaces()) {
					
					interfaces.add(inter);
				}
				
				currentClass = currentClass.getSuperclass();
			}
		
		return new ArrayList<>(interfaces);
	}
	
	private Class<?> determineProxySuperclass() {
		
		Class<?> superType = this.targetClass.getSuperclass();
		
		while(superType != Object.class) {
			
			boolean superAccessible = ByteBuddyClassUtils.checkAccessible(superType);
			
			if(!Modifier.isFinal(superType.getModifiers()) && superAccessible) {
				
				break;
			}
			
			superType = superType.getSuperclass();
		}
		
		return superType;
	}
}
