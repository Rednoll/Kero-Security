package com.kero.security.core.property.configurator;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.interceptor.DenyInterceptorImpl;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public class SinglePropertyConfigurator {

	private Property property;
	private CodeAccessSchemeConfigurator schemeConf;
	
	public SinglePropertyConfigurator(CodeAccessSchemeConfigurator schemeConf, Property property) {
		
		this.schemeConf = schemeConf;
		this.property = property;
	}
	
	public CodeAccessSchemeConfigurator cd() {
		
		return schemeConf;
	}
	
	public SinglePropertyConfigurator propagateRole(String from, String to) {
		
		KeroAccessAgent agent = schemeConf.getAgent();
		
		property.addRolePropagation(agent.getOrCreateRole(from), agent.getOrCreateRole(to));
	
		return this;
	}
	
	public SinglePropertyConfigurator defaultGrant() {
		
		return defaultAccess(Access.GRANT);
	}
	
	public SinglePropertyConfigurator defaultDeny() {
		
		return defaultAccess(Access.DENY);
	}
	
	public SinglePropertyConfigurator defaultAccess(Access role) {

		property.setDefaultAccess(role);
		
		return this;
	}
	
	public SinglePropertyConfigurator grantFor(String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		return grantFor(roles);
	}
	
	public SinglePropertyConfigurator grantFor(Collection<Role> roles) {
		
		property.grantRoles(roles);
		
		return this;
	}
	
	public SinglePropertyConfigurator denyFor(String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		return denyFor(roles);
	}
	
	public SinglePropertyConfigurator denyFor(Collection<Role> roles) {
		
		property.denyRoles(roles);
		
		return this;
	}
	
	public SinglePropertyConfigurator denyWithInterceptor(Function<Object, Object> silentInterceptor, String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		return denyWithInterceptor(silentInterceptor, roles);
	}
	
	public SinglePropertyConfigurator denyWithInterceptor(Function<Object, Object> function, Set<Role> roles) {
			
		return denyWithInterceptor(createInterceptor(function, roles));
	}
	
	public SinglePropertyConfigurator denyWithInterceptor(DenyInterceptor interceptor) {
		
		if(interceptor.getRoles().isEmpty()) {
			
			defaultDeny();
			return defaultInterceptor(interceptor);
		}
		else {
			
			property.denyRoles(interceptor.getRoles());
			return addDenyInterceptor(interceptor);
		}
	}

	public SinglePropertyConfigurator addDenyInterceptor(Function<Object, Object> function, String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		return addDenyInterceptor(function, roles);
	}
	
	public SinglePropertyConfigurator addDenyInterceptor(Function<Object, Object> function, Set<Role> roles) {
		
		return addDenyInterceptor(createInterceptor(function, roles));
	}
	
	public SinglePropertyConfigurator addDenyInterceptor(DenyInterceptor interceptor) {
		
		if(interceptor.getRoles() == null || interceptor.getRoles().isEmpty()) return defaultInterceptor(interceptor);
		
		property.addInterceptor(interceptor);
		
		return this;
	}
	
	public SinglePropertyConfigurator defaultInterceptor(Function<Object, Object> function) {
		
		return defaultInterceptor(createInterceptor(function, Collections.EMPTY_SET));
	}
	
	public SinglePropertyConfigurator defaultInterceptor(DenyInterceptor interceptor) {
		
		property.setDefaultInterceptor(interceptor);
		
		return this;
	}
	
	private DenyInterceptorImpl createInterceptor(Function<Object, Object> function, Set<Role> roles) {
	
		return new DenyInterceptorImpl(this.schemeConf.getScheme(), roles, function);
	}
}
