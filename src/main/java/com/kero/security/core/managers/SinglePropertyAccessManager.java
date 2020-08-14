package com.kero.security.core.managers;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.interceptor.DenyInterceptorImpl;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;

public class SinglePropertyAccessManager {

	private Property property;
	private KeroAccessManager manager;
	
	public SinglePropertyAccessManager(KeroAccessManager manager, Property property) {
		
		this.manager = manager;
		this.property = property;
	}
	
	public SinglePropertyAccessManager defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public SinglePropertyAccessManager defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public SinglePropertyAccessManager defaultRule(AccessRule rule) {

		property.setDefaultRule(rule);
		
		return this;
	}
	
	public SinglePropertyAccessManager grantFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		setAccessible(roles, true);
		
		return this;
	}
	
	public SinglePropertyAccessManager denyFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		setAccessible(roles, false);
		
		return this;
	}
	
	public SinglePropertyAccessManager setAccessible(Set<Role> roles, boolean accessible) {
		
		if(roles.isEmpty()) return this;
	
		property.addRule(new AccessRuleImpl(roles, accessible));
		
		return this;
	}
	
	public SinglePropertyAccessManager denyWithInterceptor(Function<Object, Object> silentInterceptor, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		return denyWithInterceptor(silentInterceptor, roles);
	}
	
	public SinglePropertyAccessManager denyWithInterceptor(Function<Object, Object> function, Set<Role> roles) {
			
		return denyWithInterceptor(createInterceptor(function, roles));
	}
	
	public SinglePropertyAccessManager denyWithInterceptor(DenyInterceptor interceptor) {
		
		if(interceptor.getRoles().isEmpty()) {
			
			defaultDeny();
			return defaultInterceptor(interceptor);
		}
		else {
			
			property.addRule(new AccessRuleImpl(interceptor.getRoles(), false));
			return addDenyInterceptor(interceptor);
		}
	}

	public SinglePropertyAccessManager addDenyInterceptor(Function<Object, Object> function, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		return addDenyInterceptor(function, roles);
	}
	
	public SinglePropertyAccessManager addDenyInterceptor(Function<Object, Object> function, Set<Role> roles) {
		
		return addDenyInterceptor(createInterceptor(function, roles));
	}
	
	public SinglePropertyAccessManager addDenyInterceptor(DenyInterceptor interceptor) {
		
		if(interceptor.getRoles() == null || interceptor.getRoles().isEmpty()) return defaultInterceptor(interceptor);
		
		property.addInterceptor(interceptor);
		
		return this;
	}
	
	public SinglePropertyAccessManager defaultInterceptor(Function<Object, Object> function) {
		
		return defaultInterceptor(createInterceptor(function, Collections.EMPTY_SET));
	}
	
	public SinglePropertyAccessManager defaultInterceptor(DenyInterceptor interceptor) {
		
		property.setDefaultInterceptor(interceptor);
		
		return this;
	}
	
	private DenyInterceptorImpl createInterceptor(Function<Object, Object> function, Set<Role> roles) {
	
		return new DenyInterceptorImpl(roles, function);
	}
}
