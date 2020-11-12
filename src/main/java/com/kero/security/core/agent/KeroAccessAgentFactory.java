package com.kero.security.core.agent;

import com.kero.security.core.agent.configurator.KeroAccessAgentConfigurator;

public interface KeroAccessAgentFactory {

	public KeroAccessAgent create();
	public void addConfigurator(KeroAccessAgentConfigurator conf);
}
