package com.kero.security.core.type;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.rmi.AccessException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType.Builder.MethodDefinition.ReceiverTypeDefinition;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class ProtectedTypeClass extends ProtectedTypeBase implements InvocationHandler {

	private Class<?> proxyClass = null;
	
	private Field originalField = null;
	private Field rolesField = null;
	
	private Map<Property, List<AccessRule>> cashedRules;
	private Map<String, Property> fullPropertiesDict;
	
	public ProtectedTypeClass() {
		super();
	
	}
	
	public ProtectedTypeClass(KeroAccessManager manager, Class<?> type, AccessRule defaultRule) {
		super(manager, type, defaultRule);
	
	}
	
	public void updateProxyClass() throws Exception {
		
		ReceiverTypeDefinition<?> receiver = new ByteBuddy()
			.subclass(type)
			.defineField("original", type, Visibility.PRIVATE)
			.defineField("roles", TypeDescription.Generic.Builder.parameterizedType(Set.class, Role.class).build(), Visibility.PRIVATE)
			.defineConstructor(Visibility.PUBLIC)
			.withParameters(TypeDescription.Generic.Builder.rawType(type).build(),
				TypeDescription.Generic.Builder.parameterizedType(Set.class, Role.class).build())
			.intercept(MethodCall.invoke(type.getConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("roles").setsArgumentAt(1))));
			
		fullPropertiesDict.forEach((propertyName, property)-> {
			
			receiver
				.method(new ElementMatcher<MethodDescription>() {
	
					@Override
					public boolean matches(MethodDescription target) {
						
						target.getName();
						
						return false;
					}
				})
				.intercept(InvocationHandlerAdapter.of(this)); //CREATE PROCESSOR
		});
		
		receiver.method(new ElementMatcher<MethodDescription>() {

			@Override
			public boolean matches(MethodDescription target) {
				
				return false;
			}
		});
		
		this.proxyClass = receiver
			.make()
			.load(ClassLoader.getSystemClassLoader())
			.getLoaded();
			
		this.originalField = this.proxyClass.getDeclaredField("original");
		this.originalField.setAccessible(true);
 
		this.rolesField = this.proxyClass.getDeclaredField("roles");
		this.rolesField.setAccessible(true);
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		
		Object original = originalField.get(proxy);
		Set<Role> roles = (Set<Role>) rolesField.get(proxy);
		
		String name = method.getName();
		
		if(name.startsWith("get")) {
			
			name = name.replaceFirst("get", "");
			name = name.toLowerCase();
		}
		
		Property property = fullPropertiesDict.get(name);
		
		List<AccessRule> rules = cashedRules.getOrDefault(property, Collections.EMPTY_LIST);
		
		Set<Role> processedRoles = new HashSet<>();
		
		for(AccessRule rule : rules) {
			
			if(rule.accessible(roles)) {
				
				return method.invoke(original, args);
			}
			
			processedRoles.addAll(rule.getRoles());
		}
		
		for(AccessRule rule : rules) {
			
			if(rule.hasSilentInterceptor()) {
				
				return rule.processSilentInterceptor(original);
			}
		}

		if(processedRoles.containsAll(roles)) throw new AccessException("Access forbidden for: "+name+"!");
		
		if(property.hasDefaultRule()) {
			
			AccessRule propertyDefaultRule = property.getDefaultRule();
		
			if(propertyDefaultRule.accessible(roles)) {
			
				return method.invoke(original, args);
			}
			else if(propertyDefaultRule.hasSilentInterceptor()) {
				
				return propertyDefaultRule.processSilentInterceptor(original);
			}
			else {
				
				throw new AccessException("Access forbidden for: "+name+"!");
			}
		}
		
		AccessRule defaultTypeRule = property.getOwner().getDefaultRule();
		
		if(defaultTypeRule.accessible(roles)) {
			
			return method.invoke(original, args);
		}
		else if(defaultTypeRule.hasSilentInterceptor()) {
			
			return defaultTypeRule.processSilentInterceptor(original);
		}
		else {
			
			throw new AccessException("Access forbidden for: "+name+"!");
		}
	}
	
	public <T> T protect(T object, Set<Role> roles) throws Exception {
		
		return (T) proxyClass.getConstructor(this.type, roles.getClass()).newInstance(object, roles);	
	}
	
	public void collectRules(Map<String, Property> propertiesDict, Map<Property, List<AccessRule>> rules, Map<String, Set<Role>> processedRoles) {
		
		collectLocalRules(propertiesDict, rules, processedRoles);
		collectFromInterfaces(propertiesDict, rules, processedRoles);
		collectFromSuperclass(propertiesDict, rules, processedRoles);
	}
	
	protected void collectFromSuperclass(Map<String, Property> propertiesDict, Map<Property, List<AccessRule>> rules, Map<String, Set<Role>> processedRoles) {
		
		Class<?> superclass = type.getSuperclass();
		
		while(superclass != null && superclass != Object.class) {
			
			ProtectedType supeclassType = manager.getType(superclass);
			
			if(supeclassType != null) {
				
				supeclassType.collectRules(propertiesDict, rules, processedRoles);
			}
			
			superclass = superclass.getSuperclass();
		}
	}
}
