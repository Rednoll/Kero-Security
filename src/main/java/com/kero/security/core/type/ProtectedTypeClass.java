package com.kero.security.core.type;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

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

public class ProtectedTypeClass extends ProtectedTypeBase implements InvocationHandler {

	private Class<?> proxyClass = null;
	
	private Field originalField = null;
	private Field rolesField = null;
	
	private Map<Property, List<AccessRule>> cashedRules;
	private Map<String, Property> fullPropertiesDict;
	
	public ProtectedTypeClass() {
		super();
	
	}
	
	public ProtectedTypeClass(KeroAccessManager manager, Class<?> type, AccessRule defaultRule) throws Exception {
		super(manager, type, defaultRule);
	
		this.proxyClass = new ByteBuddy()
				.subclass(type)
				.defineField("original", type, Visibility.PRIVATE)
				.defineField("roles", TypeDescription.Generic.Builder.parameterizedType(Set.class, Role.class).build(), Visibility.PRIVATE)
				.defineConstructor(Visibility.PUBLIC)
				.withParameters(TypeDescription.Generic.Builder.rawType(this.type).build(),
					TypeDescription.Generic.Builder.parameterizedType(Set.class, Role.class).build())
				.intercept(MethodCall.invoke(type.getConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("roles").setsArgumentAt(1))))
				.method(ElementMatchers.isPublic())
				.intercept(InvocationHandlerAdapter.of(this))
				.make()
				.load(ClassLoader.getSystemClassLoader())
				.getLoaded();
		
		this.originalField = this.proxyClass.getDeclaredField("original");
		this.originalField.setAccessible(true);
 
		this.rolesField = this.proxyClass.getDeclaredField("roles");
		this.rolesField.setAccessible(true);
	}
	
	public void updateRules() {
		
		this.cashedRules = collectRules();
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		
		updateRules(); //STUB!
		
		Object original = originalField.get(proxy);
		Set<Role> roles = new HashSet<>((Set<Role>) rolesField.get(proxy));
		
		String name = method.getName();
		
		if(name.startsWith("get")) {
			
			name = name.replaceFirst("get", "");
			name = name.toLowerCase();
		}
		
		Property property = fullPropertiesDict.get(name);
		
		if(property != null) {
			
			List<AccessRule> rules = cashedRules.getOrDefault(property, Collections.EMPTY_LIST);

			buildSequencesForProperty(property, rules);
			
			Set<Role> processedRoles = new HashSet<>();
			
			for(AccessRule rule : rules) {
			
				if(!rule.manage(roles)) continue;
					
				if(rule.accessible(roles)) {
					
					return method.invoke(original, args);
				}
				else if(rule.isDisallower()) {
				
					roles.removeAll(rule.getRoles());
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
			
				return property.getDefaultRule().process(original, method, args, processedRoles);
			}
			else {
				
				ProtectedType propertyOwner = property.getOwner();
				
				return propertyOwner.getDefaultRule().process(original, method, args, processedRoles);
			}
		}

		return this.defaultRule.process(original, method, args, roles);
	}
	
	public <T> T protect(T object, Set<Role> roles) throws Exception {
		
		return (T) proxyClass.getConstructor(this.type, Set.class).newInstance(object, roles);	
	}
	
	public void buildSequencesForProperty(Property property, List<AccessRule> rules) {
		
		SortedSet<Role> denyRoles = new TreeSet<>();
		SortedSet<Role> grantRoles = new TreeSet<>();
		
		for(AccessRule rule : rules) {
			
			if(rule.isAllower()) {
				
				for(Role role : rule.getRoles()) {
					
					if(!denyRoles.contains(role)) {
						
						grantRoles.add(role);
					}
				}
			}
			else {
				
				for(Role role : rule.getRoles()) {
					
					if(!grantRoles.contains(role)) {
						
						denyRoles.add(role);
					}
				}
			}
		}
		
		System.out.println("Property: "+property.getName());
			
		String grantRolesMessage = "";
		
		for(Role role : grantRoles) {
			
			grantRolesMessage += role.getName()+"("+role.getPriority()+") ";
		}
		
		System.out.println("Grant chanin: "+grantRolesMessage);
		
		String denyRolesMessage = "";
		
		for(Role role : denyRoles) {
			
			denyRolesMessage += role.getName()+"("+role.getPriority()+") ";
		}
		
		System.out.println("Deny chanin: "+denyRolesMessage);
	}
	
	public void collectRules(Map<String, Property> propertiesDict, Map<Property, List<AccessRule>> rules, Map<String, Set<Role>> processedRoles) {
		
		collectLocalRules(propertiesDict, rules, processedRoles);
		collectFromInterfaces(propertiesDict, rules, processedRoles);
		collectFromSuperclass(propertiesDict, rules, processedRoles);
		
		fullPropertiesDict = propertiesDict; //TODO: SIDE EFFECT
	}
	
	protected void collectFromSuperclass(Map<String, Property> propertiesDict, Map<Property, List<AccessRule>> rules, Map<String, Set<Role>> processedRoles) {
		
		Class<?> superclass = type.getSuperclass();
		
		while(superclass != Object.class) {
			
			ProtectedType supeclassType = manager.getOrCreateType(superclass);

			supeclassType.collectRules(propertiesDict, rules, processedRoles);

			superclass = superclass.getSuperclass();
		}
	}
}
