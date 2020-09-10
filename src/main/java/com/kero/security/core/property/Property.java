package com.kero.security.core.property;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.DefaultRuleOwner;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public interface Property extends DefaultRuleOwner {

	public void addRolePropagation(Role from, Role to);
	public Set<Role> propagateRoles(Collection<Role> roles);
	
	public void addRule(AccessRule rule);
	
	public void setDefaultInterceptor(DenyInterceptor interceptor);
	public boolean hasDefaultInterceptor();
	public DenyInterceptor getDefaultInterceptor();
	
	public void addInterceptor(DenyInterceptor interceptor);
	
	public void inherit(Property parent);
	
	public String getName();
	
	public List<AccessRule> getRules();
	public List<DenyInterceptor> getInterceptors();
	
	public Map<Role, Role> getRolesPropagation();
	
//	public ProtectedType getOwner();
}
