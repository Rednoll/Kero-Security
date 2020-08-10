package com.kero.security.core.managers;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.SimpleAccessRule;

public class SinglePropertyAccessManager {

	private Property property;
	
	public SinglePropertyAccessManager(Property property) {
		
		this.property = property;
	}
	
	public SinglePropertyAccessManager defaultGrant() {
		
		return defaultRule(SimpleAccessRule.GRANT_ALL);
	}
	
	public SinglePropertyAccessManager defaultDeny() {
		
		return defaultRule(SimpleAccessRule.DENY_ALL);
	}
	
	public SinglePropertyAccessManager defaultRule(AccessRule rule) {

		property.setDefaultRule(rule);
		
		return this;
	}
	
	public SinglePropertyAccessManager grantFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(Role.getOrCreate(name));
		}
		
		setAccessible(roles, true);
		
		return this;
	}
	
	public SinglePropertyAccessManager denyFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(Role.getOrCreate(name));
		}
		
		setAccessible(roles, false);
		
		return this;
	}
	
	public SinglePropertyAccessManager setAccessible(Set<Role> roles, boolean accessible) {
		
		if(roles.isEmpty()) return this;
	
		property.addRule(new SimpleAccessRule(roles, accessible, null));
		
		return this;
	}
	
	public SinglePropertyAccessManager denyWithInterceptor(Function<Object, Object> silentInterceptor, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(Role.getOrCreate(name));
		}
		
		return denyWithInterceptor(silentInterceptor, roles);
	}
		
	public SinglePropertyAccessManager denyWithInterceptor(Function<Object, Object> silentInterceptor, Set<Role> roles) {
			
		if(roles.isEmpty()) return this;
		
		property.addRule(new SimpleAccessRule(roles, false, silentInterceptor));
		
		return this;
	}
}
