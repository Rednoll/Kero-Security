package com.kero.security.core.scheme;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class AccessSchemeCacheWrapTest {
	
	@Test
	public void test() {
		
		Set<Role> roles = new HashSet<>();
			roles.add(new RoleImpl("OWNER"));
			roles.add(new RoleImpl("FRIEND"));
		
		AccessScheme schemeMock = Mockito.mock(AccessScheme.class);
		Mockito.when(schemeMock.prepareAccessConfiguration(roles)).thenReturn(new PreparedAccessConfigurationImpl());
		
		AccessScheme cachedScheme = AccessScheme.addCacheWrap(schemeMock);
		
		cachedScheme.prepareAccessConfiguration(roles);
		cachedScheme.prepareAccessConfiguration(roles);
		
		Mockito.verify(schemeMock, Mockito.times(1)).prepareAccessConfiguration(Mockito.anyCollection());
	}
}
