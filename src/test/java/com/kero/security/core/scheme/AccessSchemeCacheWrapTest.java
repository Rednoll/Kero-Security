package com.kero.security.core.scheme;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.access.Access;
import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class AccessSchemeCacheWrapTest {
	
	@Test
	public void prepareAccessConfiguration() {
		
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
	
	@Test
	public void forwardedTest() {
		
		AccessScheme schemeMock = Mockito.mock(AccessScheme.class);
		AccessScheme cachedScheme = AccessScheme.addCacheWrap(schemeMock);
		
		cachedScheme.collectProperties();
		cachedScheme.createLocalProperty("");
		cachedScheme.getAgent();
		cachedScheme.getDefaultAccess();
		cachedScheme.getLocalProperties();
		cachedScheme.getLocalProperty("");
		cachedScheme.getName();
		cachedScheme.getOrCreateLocalProperty("");
		cachedScheme.getParent();
		cachedScheme.getParentProperty("");
		cachedScheme.getTypeClass();
		cachedScheme.hasDefaultAccess();
		cachedScheme.hasLocalProperty("");
		cachedScheme.isInherit();
		cachedScheme.setDefaultAccess(Access.UNKNOWN);
		cachedScheme.setInherit(true);
		
		Mockito.verify(schemeMock, Mockito.times(1)).collectProperties();
		Mockito.verify(schemeMock, Mockito.times(1)).createLocalProperty("");
		Mockito.verify(schemeMock, Mockito.times(1)).getAgent();
		Mockito.verify(schemeMock, Mockito.times(1)).getDefaultAccess();
		Mockito.verify(schemeMock, Mockito.times(1)).getLocalProperties();
		Mockito.verify(schemeMock, Mockito.times(1)).getLocalProperty("");
		Mockito.verify(schemeMock, Mockito.times(1)).getName();
		Mockito.verify(schemeMock, Mockito.times(1)).getOrCreateLocalProperty("");
		Mockito.verify(schemeMock, Mockito.times(1)).getParent();
		Mockito.verify(schemeMock, Mockito.times(1)).getParentProperty("");
		Mockito.verify(schemeMock, Mockito.times(1)).getTypeClass();
		Mockito.verify(schemeMock, Mockito.times(1)).hasDefaultAccess();
		Mockito.verify(schemeMock, Mockito.times(1)).hasLocalProperty("");
		Mockito.verify(schemeMock, Mockito.times(1)).isInherit();
		Mockito.verify(schemeMock, Mockito.times(1)).setDefaultAccess(Access.UNKNOWN);
		Mockito.verify(schemeMock, Mockito.times(1)).setInherit(true);
	}
}
