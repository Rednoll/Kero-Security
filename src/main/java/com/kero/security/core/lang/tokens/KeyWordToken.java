package com.kero.security.core.lang.tokens;

public class KeyWordToken extends KsdlTokenBase {

	private String name;
	
	public KeyWordToken(String name) {
		
		this.name = name;
	}
	
	
	@Override
	public String toString() {
		return "KeyWordToken [name=" + name + "]";
	}

	public String getName() {
		
		return this.name;
	}
}
