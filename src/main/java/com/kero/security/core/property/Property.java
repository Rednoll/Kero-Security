package com.kero.security.core.property;

import java.util.List;

import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.type.ProtectedType;

public interface Property {

	public void setDefaultRule(AccessRule rule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
	
	public void addRule(AccessRule rule);
	
	public String getName();
	
	public List<AccessRule> getRules();
	
	public ProtectedType getOwner();
}
