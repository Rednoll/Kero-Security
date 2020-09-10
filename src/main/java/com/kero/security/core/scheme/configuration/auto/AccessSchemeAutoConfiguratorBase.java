package com.kero.security.core.scheme.configuration.auto;

import com.kero.security.core.KeroAccessAgent;

public abstract class AccessSchemeAutoConfiguratorBase implements AccessSchemeAutoConfigurator {

	protected KeroAccessAgent agent;
	
	public AccessSchemeAutoConfiguratorBase(KeroAccessAgent manager) {
		
		this.agent = manager;
	}
}
