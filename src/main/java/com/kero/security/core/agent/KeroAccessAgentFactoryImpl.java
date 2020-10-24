package com.kero.security.core.agent;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.agent.configuration.KeroAccessAgentConfigurator;

public class KeroAccessAgentFactoryImpl implements KeroAccessAgentFactory {

	private static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	private Set<KeroAccessAgentConfigurator> configurators = new HashSet<>();
	
	public KeroAccessAgentFactoryImpl() {
	
	}
	
	@Override
	public KeroAccessAgent create() {
		
		KeroAccessAgent agent = new KeroAccessAgentImpl();
		
		for(KeroAccessAgentConfigurator conf : configurators) {
			
			LOGGER.debug("Apply configurator: "+conf+" to new agent.");
			conf.configure(agent);
		}
		
		return agent;
	}
	
	@Override
	public void addConfigurator(KeroAccessAgentConfigurator conf) {
		
		this.configurators.add(conf);
		
		LOGGER.debug("Add configurator: "+conf+" to agent factory.");
	}
}
