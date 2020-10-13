package com.kero.security.core.property;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.access.Access;
import com.kero.security.core.config.action.Action;
import com.kero.security.core.role.Role;

public class PropertyTest {

	@Test
	public void verifyEmpty() {
		
		Property empty = Property.EMPTY;
	
		assertEquals(empty.accessible(Collections.emptySet()), Access.UNKNOWN);
		assertEquals(empty.determineInterceptor(Collections.emptySet()), null);
		assertEquals(empty.getDefaultAccess(), Access.UNKNOWN);
		assertEquals(empty.getDefaultInterceptor(), null);
		assertEquals(empty.getDenyRoles(), Collections.emptySet());
		assertEquals(empty.getGrantRoles(), Collections.emptySet());
		assertEquals(empty.getInterceptors(), Collections.emptyList());
		assertEquals(empty.getName(), null);
		assertEquals(empty.getParent(), Property.EMPTY);
		assertEquals(empty.prepare(Collections.emptySet()), Action.EMPTY);
		
		Role role = Mockito.mock(Role.class);
		assertTrue(empty.propagateRole(role) == role);
		
		assertEquals(empty.propagateRoles(Collections.emptySet()), Collections.emptySet());
	}
}
