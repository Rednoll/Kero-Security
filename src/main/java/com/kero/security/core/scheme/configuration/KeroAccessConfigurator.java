package com.kero.security.core.scheme.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.KeroAccessAgent;

public class KeroAccessConfigurator {

	protected static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	private KeroAccessAgent agent;
	
	public KeroAccessConfigurator(KeroAccessAgent agent) {
		
		this.agent = agent;
	}
	
	public AccessSchemeConfigurator scheme(Class<?> type) {
		
		return new AccessSchemeConfigurator(agent, agent.getOrCreateScheme(type));
	}
}
