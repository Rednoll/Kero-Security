package com.kero.security.core.property;

import java.lang.reflect.Method;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public interface Property {

	public void setDefaultRule(AccessRule rule);
	
	public void addRule(AccessRule rule);
	
	public Object tryInvoke(Object original, Method method, Object[] args, Set<Role> roles) throws Exception;
	
	public String getName();
}
