package com.kero.security.core.scheme.definition;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;

public class ClassAccessSchemeDefinition implements AccessSchemeDefinition {

	private KeroAccessAgent agent;
	
	private Class<?> typeClass;
	private String name;
	
	public ClassAccessSchemeDefinition(KeroAccessAgent agent, String name, Class<?> typeClass) {
	
		this.agent = agent;
		this.name = name;
		this.typeClass = typeClass;
	}
	
	@Override
	public AccessScheme createScheme() {
		
		return new ClassAccessScheme(this.agent, this.name, this.typeClass);
	}
	
	@Override
	public Class<?> getTypeClass() {
		
		return this.typeClass;
	}
	
	@Override
	public KeroAccessAgent getAgent() {
		
		return this.agent;
	}
	
	@Override
	public void setName(String name) {
		
		this.name = name;
	}
	
	@Override
	public String getName() {
		
		return this.name;
	}
}
