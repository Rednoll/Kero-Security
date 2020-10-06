package com.kero.security.core.scheme.definition;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.scheme.AccessScheme;

public interface AccessSchemeDefinition {
	
	public void setName(String name);
	public String getName();
	
	public Class<?> getTypeClass();

	public KeroAccessAgent getAgent();
	
	public AccessScheme createScheme();
}
