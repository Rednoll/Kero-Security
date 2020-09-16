package com.kero.security.lang.tokens;

import com.kero.security.lang.nodes.DefaultRuleNode;

public enum DefaultRuleToken implements KsdlToken {

	EMPTY(null), GRANT(true), DENY(false);
	
	private Boolean defaultAccessible;
	
	private DefaultRuleToken(Boolean defaultAccessible) {
		
		this.defaultAccessible = defaultAccessible;
	}
	
	public DefaultRuleNode toNode() {
		
		if(defaultAccessible == null) return DefaultRuleNode.EMPTY;
		if(defaultAccessible) return DefaultRuleNode.GRANT;
		
		return DefaultRuleNode.DENY;
	}
	
	@Override
	public String toString() {
		
		return "DefaultRuleToken [defaultAccessible=" + defaultAccessible + "]";
	}

	public Boolean getDefaultAccessible() {
		
		return this.defaultAccessible;
	}
}
