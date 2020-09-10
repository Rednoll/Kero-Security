package com.kero.security.core.scheme.configuration.auto;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.SchemeNodeMap;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.provider.KsdlProvider;

public class KsdlAccessSchemeConfigurator extends AccessSchemeAutoConfiguratorBase {

	protected KsdlProvider provider;
	
	public KsdlAccessSchemeConfigurator(KeroAccessManager manager, KsdlProvider provider) {
		super(manager);
	
		this.provider = provider;
	}

	@Override
	public void configure(AccessScheme scheme) {
		
		RootNodeList roots = provider.getRoots();
	
		SchemeNodeMap schemeNodes = roots.getSchemeNodes();
		
		SchemeNode schemeNode = schemeNodes.get(scheme.getAliase());

		//REMOVE NULL CHECK -> NULL OBJECT
		if(schemeNode != null) {
			
			schemeNode.interpret(scheme);
		}
	}
}
