package com.kero.security.lang.nodes;

import com.kero.security.core.DefaultAccessOwner;
import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;

public enum DefaultAccessNode implements KsdlNode {
	
	EMPTY(Access.UNKNOWN), GRANT(Access.GRANT), DENY(Access.DENY);

	private Access access;
		
	private DefaultAccessNode(Access access) {
		
		this.access = access;
	}
	
	public void interpret(KeroAccessAgent manager, DefaultAccessOwner target) {
		
		target.setDefaultAccess(this.access);
	}
}
