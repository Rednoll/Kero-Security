package com.kero.security.lang.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.provider.resource.KsdlTextResource;

public class TextualProviderTest {

	@Test
	public void getRoots() {
		
		String data = "scheme TestScheme(D) {\n"
				+ "text(G): +OWNER -FRIEND\n"
				+ "- propagation: OWNER -> FRIEND\n"
				+ "}";
		
		KsdlTextResource resource = Mockito.mock(KsdlTextResource.class);
		Mockito.when(resource.getRawText()).thenReturn(data);
		
		TextualProvider provider = new TextualProvider(resource);
	
		RootNodeList roots = provider.getRoots();
		
		assertEquals(roots.size(), 1);
		assertTrue(roots.get(0) instanceof SchemeNode);
	}
}
