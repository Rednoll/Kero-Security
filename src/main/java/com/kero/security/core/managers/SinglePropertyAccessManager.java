package com.kero.security.core.managers;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.interceptor.FailureInterceptorImpl;
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
	
	public SinglePropertyAccessManager failureInterceptor(Function<Object, Object> function, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		return failureInterceptor(function, roles);
	}
	
	
	public SinglePropertyAccessManager defaultInterceptor(Function<Object, Object> function) {
		
		property.setDefaultInterceptor(new FailureInterceptorImpl(Collections.EMPTY_SET, function));
		
		return this;
	}
	
	public SinglePropertyAccessManager failureInterceptor(Function<Object, Object> function, Set<Role> roles) {
		
		if(roles == null || roles.isEmpty()) return defaultInterceptor(function);
		
		property.addInterceptor(new FailureInterceptorImpl(roles, function));
		
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
			
		if(roles.isEmpty()) return this;
		
		property.addRule(new AccessRuleImpl(roles, false));
		
		return failureInterceptor(function, roles);
	}
}
