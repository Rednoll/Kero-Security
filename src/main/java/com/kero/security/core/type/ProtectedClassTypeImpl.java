package com.kero.security.core.type;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.exception.AccessException;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;

public class ProtectedClassTypeImpl extends ProtectedTypeBase implements ProtectedClassType, InvocationHandler {

	private Class<?> proxyClazz;
	private Field originalField;
	private Field rolesField;
	
	public ProtectedClassTypeImpl() {}
	
	public ProtectedClassTypeImpl(KeroAccessManager accessManager, Class<?> type, AccessRule defaultRule) throws Exception {
		super(accessManager, type, defaultRule);
		
		this.proxyClazz = new ByteBuddy()
			.subclass(type)
			.defineField("original", type, Visibility.PRIVATE)
			.defineField("roles", TypeDescription.Generic.Builder.parameterizedType(Set.class, Role.class).build(), Visibility.PRIVATE)
			.defineConstructor(Visibility.PUBLIC)
			.withParameters(TypeDescription.Generic.Builder.rawType(type).build(),
				TypeDescription.Generic.Builder.parameterizedType(Set.class, Role.class).build())
			.intercept(MethodCall.invoke(type.getConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("roles").setsArgumentAt(1))))
			.method(ElementMatchers.isPublic())
			.intercept(InvocationHandlerAdapter.of(this))
			.make()
			.load(ClassLoader.getSystemClassLoader())
			.getLoaded();
		
		this.originalField = this.proxyClazz.getDeclaredField("original");
		this.originalField.setAccessible(true);
		
		this.rolesField = this.proxyClazz.getDeclaredField("roles");
		this.rolesField.setAccessible(true);
	}

	@Override
	public Object protect(Object obj, Set<Role> roles) throws Exception {

		return proxyClazz.getConstructor(type, Set.class).newInstance(obj, roles);
	}
	
	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

		Object original = this.originalField.get(proxy);
		Set<Role> roles = (Set<Role>) this.rolesField.get(proxy);
		
		return tryInvoke(original, method, args, roles);
	}

	@Override
	public Object tryInvoke(Object original, Method method, Object[] args, Set<Role> roles) throws Exception {
	
		String name = method.getName();
		
		if(name.startsWith("get")) {
			
			name = name.substring(3);
			name = name.toLowerCase();
		}
		
		if(properties.containsKey(name)) {
		
			return properties.get(name).tryInvoke(original, method, args, roles);
		}
		else {
			
			Class<?>[] interfaces = type.getInterfaces();
			
			for(Class<?> inter : interfaces) {
				
				if(accessManager.hasType(inter)) {
				
					ProtectedType interType = accessManager.getType(inter);
				
					if(interType.hasProperty(name)) {
						
						return interType.tryInvoke(original, method, args, roles);
					}
				}
			}
			
			Class<?> superClass = type.getSuperclass();
			
			while(superClass != Object.class) {
			
				if(accessManager.hasType(superClass)) {
					
					ProtectedType superType = accessManager.getType(superClass);
					
					return superType.tryInvoke(original, method, args, roles);
				}
				
				superClass = superClass.getSuperclass();
			}
		}
		
		if(defaultRule.accessible(roles)) {
			
			return method.invoke(original, args);
		}
		else if(defaultRule.hasSilentInterceptor()) {
			
			return defaultRule.processSilentInterceptor(original);
		}
		else {
			
			throw new AccessException("Access denied for: "+method.getName());
		}
	}
}
