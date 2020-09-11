package com.kero.security.core.agent.factory;

import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentImpl;
import com.kero.security.core.agent.configuration.KeroAccessAgentConfigurator;

public class KeroAccessAgentFactoryImpl implements KeroAccessAgentFactory {

	private Set<KeroAccessAgentConfigurator> configurators = new HashSet<>();
	
	@Override
	public KeroAccessAgent create() {
		
		KeroAccessAgent agent = new KeroAccessAgentImpl();
		
		for(KeroAccessAgentConfigurator conf : configurators) {
			
			conf.configure(agent);
		}
		
		return agent;
	}
	
	@Override
	public void addConfigurator(KeroAccessAgentConfigurator conf) {
		
		configurators.add(conf);
	}
}
