package com.kero.security.core.config.prepared;

import com.kero.security.core.scheme.AccessScheme;

public abstract class PreparedActionBase implements PreparedAction {

	protected AccessScheme scheme;
	
	public PreparedActionBase(AccessScheme scheme) {
		
		this.scheme = scheme;
	}
}
