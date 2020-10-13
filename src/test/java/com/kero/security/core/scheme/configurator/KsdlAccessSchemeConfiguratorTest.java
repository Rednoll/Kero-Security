package com.kero.security.core.scheme.configurator;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.provider.KsdlProvider;

public class KsdlAccessSchemeConfiguratorTest {

	@Test
	public void configure() {
		
		RootNodeList roots = new RootNodeList();
	
			SchemeNode node = Mockito.mock(SchemeNode.class);
				Mockito.when(node.getName()).thenReturn("TestScheme");
				
			roots.add(node);
		
		KsdlProvider provider = Mockito.mock(KsdlProvider.class);
		Mockito.when(provider.getRoots()).thenReturn(roots);
		
		AccessScheme schemeMock = Mockito.mock(AccessScheme.class);
		Mockito.when(schemeMock.getName()).thenReturn("TestScheme");
		
		KsdlAccessSchemeConfigurator configurator = new KsdlAccessSchemeConfigurator(provider);
			configurator.configure(schemeMock);
		
		Mockito.verify(node, Mockito.times(1)).interpret(schemeMock);
	}
}
