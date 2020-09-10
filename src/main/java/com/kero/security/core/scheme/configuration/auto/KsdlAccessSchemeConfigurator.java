package com.kero.security.core.scheme.configuration.auto;

import com.kero.security.core.KeroAccessAgent;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.SchemeNodeMap;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.provider.KsdlProvider;

public class KsdlAccessSchemeConfigurator extends AccessSchemeAutoConfiguratorBase {

	protected KsdlProvider provider;
	
	public KsdlAccessSchemeConfigurator(KeroAccessAgent agent, KsdlProvider provider) {
		super(agent);
	
		this.provider = provider;
	}

	@Override
	public void configure(AccessScheme scheme) {
		
		RootNodeList roots = provider.getRoots();
	
		SchemeNodeMap schemeNodes = roots.getSchemeNodes();
		
		SchemeNode schemeNode = schemeNodes.getOrDefault(scheme.getAliase(), SchemeNode.EMPTY);

		schemeNode.interpret(scheme);
	}
}
