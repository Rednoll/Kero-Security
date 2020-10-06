package com.kero.security.core.scheme.configurator;

import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.SchemeNodeMap;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.provider.KsdlProvider;

public class KsdlAccessSchemeConfigurator extends AccessSchemeConfiguratorBase {

	protected KsdlProvider provider;
	
	public KsdlAccessSchemeConfigurator(KsdlProvider provider) {
	
		this.provider = provider;
	}

	@Override
	public void configure(AccessScheme scheme) {
		
		RootNodeList roots = provider.getRoots();
	
		SchemeNodeMap schemeNodes = roots.getSchemeNodes();
		
		SchemeNode schemeNode = schemeNodes.getOrDefault(scheme.getName(), SchemeNode.EMPTY);

		schemeNode.interpret(scheme);
	}
}
