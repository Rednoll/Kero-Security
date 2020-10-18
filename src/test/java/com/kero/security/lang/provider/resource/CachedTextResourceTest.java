package com.kero.security.lang.provider.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CachedTextResourceTest {

	@Test
	public void getRawText() {
		
		KsdlTextResource resource = Mockito.mock(KsdlTextResource.class);
		Mockito.when(resource.getRawText()).thenReturn("");
		
		TextResourceCacheWrap cached = new TextResourceCacheWrap(resource);
	
		cached.getRawText();
		cached.getRawText();
		
		Mockito.verify(resource, Mockito.times(1)).getRawText();
	}
	
	@Test
	public void doubleWrapCheck() {
		
		KsdlTextResource resource = Mockito.mock(KsdlTextResource.class);
		Mockito.when(resource.getRawText()).thenReturn("");
		
		KsdlTextResourceWrap wrap = (KsdlTextResourceWrap) KsdlTextResource.addCacheWrap(resource);
	
		assertEquals(KsdlTextResource.addCacheWrap(wrap), wrap);
	}
}
