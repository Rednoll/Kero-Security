package com.kero.security.core.agent.factory;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.configuration.KeroAccessAgentConfigurator;

public interface KeroAccessAgentFactory {

	public KeroAccessAgent create();
	public void addConfigurator(KeroAccessAgentConfigurator conf);
}
