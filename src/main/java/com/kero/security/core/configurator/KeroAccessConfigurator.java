package com.kero.security.core.configurator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public class KeroAccessConfigurator {

	protected static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	private KeroAccessAgent agent;
	
	public KeroAccessConfigurator(KeroAccessAgent agent) {
		
		this.agent = agent;
	}
	
	public CodeAccessSchemeConfigurator scheme(Class<?> type) {
		
		return new CodeAccessSchemeConfigurator(agent, agent.getOrCreateScheme(type));
	}
}
