package com.kero.security.core.property;

import java.util.List;

import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.AccessScheme;

public interface Property {

	public void setDefaultRule(AccessRule rule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
	
	public void addRule(AccessRule rule);
	
	public void setDefaultInterceptor(DenyInterceptor interceptor);
	public boolean hasDefaultInterceptor();
	public DenyInterceptor getDefaultInterceptor();
	
	public void addInterceptor(DenyInterceptor interceptor);
	
	public void inherit(Property parent);
	
	public String getName();
	
	public List<AccessRule> getRules();
	public List<DenyInterceptor> getInterceptors();
	
//	public ProtectedType getOwner();
}
