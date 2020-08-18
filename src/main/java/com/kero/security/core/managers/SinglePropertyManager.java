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

public class SinglePropertyManager {

	private Property property;
	private AccessSchemeManager schemeManager;
	
	public SinglePropertyManager(AccessSchemeManager schemeManager, Property property) {
		
		this.schemeManager = schemeManager;
		this.property = property;
	}
	
	public SinglePropertyManager defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public SinglePropertyManager defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public SinglePropertyManager defaultRule(AccessRule rule) {

		property.setDefaultRule(rule);
		
		return this;
	}
	
	public SinglePropertyManager grantFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(schemeManager.getManager().getOrCreateRole(name));
		}
		
		setAccessible(roles, true);
		
		return this;
	}
	
	public SinglePropertyManager denyFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(schemeManager.getManager().getOrCreateRole(name));
		}
		
		setAccessible(roles, false);
		
		return this;
	}
	
	public SinglePropertyManager setAccessible(Set<Role> roles, boolean accessible) {
		
		if(roles.isEmpty()) return this;
	
		property.addRule(new AccessRuleImpl(roles, accessible));
		
		return this;
	}
	
	public SinglePropertyManager denyWithInterceptor(Function<Object, Object> silentInterceptor, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(schemeManager.getManager().getOrCreateRole(name));
		}
		
		return denyWithInterceptor(silentInterceptor, roles);
	}
	
	public SinglePropertyManager denyWithInterceptor(Function<Object, Object> function, Set<Role> roles) {
			
		return denyWithInterceptor(createInterceptor(function, roles));
	}
	
	public SinglePropertyManager denyWithInterceptor(DenyInterceptor interceptor) {
		
		if(interceptor.getRoles().isEmpty()) {
			
			defaultDeny();
			return defaultInterceptor(interceptor);
		}
		else {
			
			property.addRule(new AccessRuleImpl(interceptor.getRoles(), false));
			return addDenyInterceptor(interceptor);
		}
	}

	public SinglePropertyManager addDenyInterceptor(Function<Object, Object> function, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(schemeManager.getManager().getOrCreateRole(name));
		}
		
		return addDenyInterceptor(function, roles);
	}
	
	public SinglePropertyManager addDenyInterceptor(Function<Object, Object> function, Set<Role> roles) {
		
		return addDenyInterceptor(createInterceptor(function, roles));
	}
	
	public SinglePropertyManager addDenyInterceptor(DenyInterceptor interceptor) {
		
		if(interceptor.getRoles() == null || interceptor.getRoles().isEmpty()) return defaultInterceptor(interceptor);
		
		property.addInterceptor(interceptor);
		
		return this;
	}
	
	public SinglePropertyManager defaultInterceptor(Function<Object, Object> function) {
		
		return defaultInterceptor(createInterceptor(function, Collections.EMPTY_SET));
	}
	
	public SinglePropertyManager defaultInterceptor(DenyInterceptor interceptor) {
		
		property.setDefaultInterceptor(interceptor);
		
		return this;
	}
	
	private DenyInterceptorImpl createInterceptor(Function<Object, Object> function, Set<Role> roles) {
	
		return new DenyInterceptorImpl(this.schemeManager.getScheme(), roles, function);
	}
}
