package com.kero.security.core.lang.tokens;

public class DefaultRuleToken extends KsdlTokenBase {

	private boolean defaultAccessible;
	
	public DefaultRuleToken(boolean defaultAccessible) {
		
		this.defaultAccessible = defaultAccessible;
	}
	
	@Override
	public String toString() {
		return "DefaultRuleToken [defaultAccessible=" + defaultAccessible + "]";
	}

	public boolean getDefaultAccessible() {
		
		return this.defaultAccessible;
	}
}
