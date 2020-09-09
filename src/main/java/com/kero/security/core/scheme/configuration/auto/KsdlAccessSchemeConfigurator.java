package com.kero.security.core.scheme.configuration.auto;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.source.KsdlSource;

public class KsdlAccessSchemeConfigurator extends AccessSchemeAutoConfiguratorBase {

	protected KsdlSource source;
	
	public KsdlAccessSchemeConfigurator(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void configure(AccessScheme scheme) {
		
	}
}
