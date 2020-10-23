package com.kero.security.core.agent;

import com.kero.security.core.agent.KeroAccessAgentFactoryImpl.Builder;

public interface KeroAccessAgentFactoryBuilder {

	public KeroAccessAgentFactory build();
	
	public Builder setMainProviderPreloading(boolean i);
}
