package com.kero.security.core.rules;

import java.lang.reflect.Method;
import java.util.Set;

import com.kero.security.core.role.Role;

public interface AccessRule {
	
	public Object process(Object original, Method method, Object[] args, Set<Role> roles) throws Exception;
	
	public Role getHighestPriorityRole();
	
	public boolean manage(Set<Role> role);

	public boolean accessible(Set<Role> roles);

	public boolean hasSilentInterceptor();
	public Object processSilentInterceptor(Object target);
	
	public Set<Role> getRoles();
	
	public boolean isAllower();
	public boolean isDisallower();
}