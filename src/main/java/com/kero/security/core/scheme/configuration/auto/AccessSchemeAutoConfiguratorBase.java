package com.kero.security.core.scheme.configuration.auto;

import com.kero.security.core.KeroAccessManager;

public abstract class AccessSchemeAutoConfiguratorBase implements AccessSchemeAutoConfigurator {

	protected KeroAccessManager manager;
	
	public AccessSchemeAutoConfiguratorBase(KeroAccessManager manager) {
		
		this.manager = manager;
	}
}
