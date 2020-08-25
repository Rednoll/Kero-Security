package com.kero.security.core.lang.tokens;

public abstract class KsdlProtectedUnitToken extends KsdlTokenBase {

	private String name;
	private Boolean defaultAccessible;
	
	public KsdlProtectedUnitToken(String name, Boolean defaultAccessible) {
		
		this.name = name;
		this.defaultAccessible = defaultAccessible;
	}
	
	public Boolean getDefaultAccessible() {
		
		return this.defaultAccessible;
	}
	
	public String getName() {
		
		return this.name;
	}
}
