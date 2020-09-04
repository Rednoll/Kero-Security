package com.kero.security.core;

import com.kero.security.core.rules.AccessRule;

public interface DefaultRuleOwner {

	public void setDefaultRule(AccessRule rule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
}
