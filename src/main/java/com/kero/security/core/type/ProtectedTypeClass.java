package com.kero.security.core.type;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.config.PreparedRule;
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
	private Field pacField = null;
	
	private Map<String, Property> cashedRules;
	private Map<Property, Set<Role>> grantChain = new HashMap<>();
	private Map<Property, Set<Role>> denyChain = new HashMap<>();
	
	private Map<Set<Role>, PreparedAccessConfiguration> configsCache = new HashMap<>();
	
	public ProtectedTypeClass() {
		super();
	
	}
	
	public ProtectedTypeClass(KeroAccessManager manager, Class<?> type, AccessRule defaultRule) throws Exception {
		super(manager, type, defaultRule);
	
		this.proxyClass = new ByteBuddy()
				.subclass(type)
				.defineField("original", type, Visibility.PRIVATE)
				.defineField("pac", PreparedRule.class, Visibility.PRIVATE)
				.defineConstructor(Visibility.PUBLIC)
				.withParameters(type, PreparedRule.class)
				.intercept(MethodCall.invoke(type.getConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1))))
				.method(ElementMatchers.isPublic())
				.intercept(InvocationHandlerAdapter.of(this))
				.make()
				.load(ClassLoader.getSystemClassLoader())
				.getLoaded();
		
		this.originalField = this.proxyClass.getDeclaredField("original");
		this.originalField.setAccessible(true);
 
		this.pacField = this.proxyClass.getDeclaredField("pac");
		this.pacField.setAccessible(true);
	}
	
	public void updateRules() {
		
		this.cashedRules = collectRules();
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		
		Object original = originalField.get(proxy);
		PreparedAccessConfiguration pac = (PreparedAccessConfiguration) pacField.get(proxy);
	
		return pac.process(original, method, args);
	}
	
	/*
	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		
		updateRules(); //STUB!
		buildChainsForProperties();
		
		Object original = originalField.get(proxy);
		Set<Role> significantRoles = new HashSet<>((Set<Role>) rolesField.get(proxy));
		
		String name = method.getName();
		
		if(name.startsWith("get")) {
			
			name = name.replaceFirst("get", "");
			name = name.toLowerCase();
		}
		
		Property property = cashedRules.get(name);
	
		if(property != null) {
		
			Set<Role> denyChain = this.denyChain.get(property);
			Set<Role> grantChain = this.grantChain.get(property);
			
			if(!Collections.disjoint(grantChain, significantRoles)) {
				
				return method.invoke(original, args);
			}
			
			for(AccessRule rule : property.getRules()) {
				
				if(rule.manage(significantRoles) && rule.hasSilentInterceptor()) {
					
					return rule.processSilentInterceptor(original);
				}
			}
		
			significantRoles.removeAll(denyChain);
		
			if(significantRoles.isEmpty()) throw new AccessException("Access denied for: "+name);

			if(property.hasDefaultRule()) {
			
				return property.getDefaultRule().process(original, method, args, significantRoles);
			}
			else {
				
				ProtectedType propertyOwner = property.getOwner();
				
				return propertyOwner.getDefaultRule().process(original, method, args, significantRoles);
			}
		}

		return this.defaultRule.process(original, method, args, significantRoles);
	}
	
	/*
	private AccessRule determineSilentInterceptor(Property property, Set<Role> roles) {
	
		List<AccessRule> rules = property.getRules();
	
		for(AccessRule rule : rules) {
			
			
		}
	}
	*/
	
	public <T> T protect(T object, Set<Role> roles) throws Exception {
		
		PreparedAccessConfiguration config = configsCache.get(roles);
		
		if(config != null) {
	
			config = prepareAccessConfiguration(roles);
			configsCache.put(roles, config);
		}
		
		return (T) proxyClass.getConstructor(this.type, PreparedAccessConfiguration.class).newInstance(object, config);	
	}
	
	private PreparedAccessConfiguration prepareAccessConfiguration(Set<Role> roles) {
		
		Map<String, PreparedRule> rules = new HashMap<>();
		
		updateRules();
		buildChainsForProperties();
		
		cashedRules.forEach((propertyName, property)-> {
			
			
		});
		
		return new PreparedAccessConfigurationImpl(rules);
	}
	
	public void buildChainsForProperties() {
	
		this.denyChain.clear();
		this.grantChain.clear();
		
		cashedRules.values().forEach((property)-> this.buildChainsForProperty(property));
	}

	public void buildChainsForProperty(Property property) {
		
		List<AccessRule> rules = property.getRules();
		
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
		
		System.out.println("Grant chain: "+grantRolesMessage);
		
		String denyRolesMessage = "";
		
		for(Role role : denyRoles) {
			
			denyRolesMessage += role.getName()+"("+role.getPriority()+") ";
		}
		
		System.out.println("Deny chain: "+denyRolesMessage);
		
		this.denyChain.put(property, denyRoles);
		this.grantChain.put(property, grantRoles);
	}
	
	public void collectRules(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles) {
		
		collectLocalRules(complexProperties, processedRoles);
		collectFromInterfaces(complexProperties, processedRoles);
		collectFromSuperclass(complexProperties, processedRoles);
	}
	
	protected void collectFromSuperclass(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles) {
		
		Class<?> superclass = type.getSuperclass();
		
		while(superclass != Object.class) {
			
			ProtectedType supeclassType = manager.getOrCreateType(superclass);

			supeclassType.collectRules(complexProperties, processedRoles);

			superclass = superclass.getSuperclass();
		}
	}
}
