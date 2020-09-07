package com.kero.security.core.scheme.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.KeroAccessManager;

public class KeroAccessConfigurator {

	protected static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	private KeroAccessManager manager;
	
	public KeroAccessConfigurator(KeroAccessManager manager) {
		
		this.manager = manager;
	}
	
	public AccessSchemeConfigurator scheme(Class<?> type) {
		
		return new AccessSchemeConfigurator(manager, manager.getOrCreateScheme(type));
	}
}
