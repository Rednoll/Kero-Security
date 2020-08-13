package com.kero.security.core.property;

import java.util.List;

import com.kero.security.core.interceptor.FailureInterceptor;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.type.ProtectedType;

public interface Property {

	public void setDefaultRule(AccessRule rule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
	
	public void addRule(AccessRule rule);
	
	public void setDefaultInterceptor(FailureInterceptor interceptor);
	public boolean hasDefaultInterceptor();
	public FailureInterceptor getDefaultInterceptor();
	
	public void addInterceptor(FailureInterceptor interceptor);
	
	public String getName();
	
	public List<AccessRule> getRules();
	public List<FailureInterceptor> getInterceptors();
	
	public ProtectedType getOwner();
}
