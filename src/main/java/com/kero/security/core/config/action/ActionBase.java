package com.kero.security.core.config.action;

import com.kero.security.core.scheme.AccessScheme;

public abstract class ActionBase implements Action {

	protected AccessScheme scheme;
	
	public ActionBase(AccessScheme scheme) {
		
		this.scheme = scheme;
	}
}
