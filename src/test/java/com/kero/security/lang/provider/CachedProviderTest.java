package com.kero.security.lang.provider;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.lang.collections.RootNodeList;

public class CachedProviderTest {

	@Test
	public void getRoots_One() {
		
		KsdlProvider provider = Mockito.mock(KsdlProvider.class);
		Mockito.when(provider.getRoots()).thenReturn(new RootNodeList());
		
		ProviderCacheWrap cached = new ProviderCacheWrap(provider);
		
		cached.getRoots();
		cached.getRoots();
		
		Mockito.verify(provider, Mockito.times(1)).getRoots();
	}
}
