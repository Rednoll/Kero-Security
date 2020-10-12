package com.kero.security.lang.provider.resource;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CachedTextResourceTest {

	@Test
	public void getRawText() {
		
		KsdlTextResource resource = Mockito.mock(KsdlTextResource.class);
		Mockito.when(resource.getRawText()).thenReturn("");
		
		CachedTextResource cached = new CachedTextResource(resource);
	
		cached.getRawText();
		cached.getRawText();
		
		Mockito.verify(resource, Mockito.times(1)).getRawText();
	}
}
