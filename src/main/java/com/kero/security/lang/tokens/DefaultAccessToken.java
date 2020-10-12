package com.kero.security.lang.tokens;

import com.kero.security.lang.nodes.DefaultAccessNode;

public enum DefaultAccessToken implements KsdlToken {

	EMPTY(null), GRANT(true), DENY(false);
	
	private Boolean defaultAccessible;
	
	private DefaultAccessToken(Boolean defaultAccessible) {
		
		this.defaultAccessible = defaultAccessible;
	}
	
	public DefaultAccessNode toNode() {
		
		if(defaultAccessible == null) return DefaultAccessNode.EMPTY;
		if(defaultAccessible) return DefaultAccessNode.GRANT;
		
		return DefaultAccessNode.DENY;
	}
	
	@Override
	public String toString() {
		
		return "DefaultRuleToken [defaultAccessible=" + defaultAccessible + "]";
	}

	public Boolean getDefaultAccessible() {
		
		return this.defaultAccessible;
	}
}
