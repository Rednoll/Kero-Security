package com.kero.security.core.property;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.access.Access;
import com.kero.security.core.config.action.Action;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class PropertyTest {

	@Test
	public void verifyEmpty() {
		
		Property empty = Property.EMPTY;
	
		assertEquals(empty.accessible(Collections.emptySet()), Access.UNKNOWN);
		assertEquals(empty.determineInterceptor(Collections.emptySet()), null);
		assertEquals(empty.getDefaultAccess(), Access.UNKNOWN);
		assertEquals(empty.hasDefaultAccess(), false);
		assertEquals(empty.getDefaultInterceptor(), null);
		assertEquals(empty.getDenyRoles(), Collections.emptySet());
		assertEquals(empty.getGrantRoles(), Collections.emptySet());
		assertEquals(empty.getInterceptors(), Collections.emptyList());
		assertEquals(empty.hasDefaultInterceptor(), false);
		assertEquals(empty.getName(), null);
		assertEquals(empty.getParent(), Property.EMPTY);
		assertEquals(empty.prepare(Collections.emptySet()), Action.EMPTY);
		assertEquals(empty.hasPropagationFor(null), false);
		
		Role role = Mockito.mock(Role.class);
		assertTrue(empty.propagateRole(role) == role);
		
		assertEquals(empty.propagateRoles(Collections.emptySet()), Collections.emptySet());
	}
	
	@Test
	public void verifyEmpty_Imutability() {
		
		Property empty = Property.EMPTY;
		
		empty.setDefaultAccess(Access.GRANT);
		assertEquals(empty.getDefaultAccess(), Access.UNKNOWN);
		
		Role owner = new RoleImpl("OWNER");
		Role friend = new RoleImpl("FRIEND");
		
		empty.addRolePropagation(owner, friend);
		assertEquals(empty.propagateRole(owner), owner);
		
		Set<Role> roles = new HashSet<>();
			roles.add(owner);
		
		empty.grantRoles(roles);
		assertTrue(empty.getGrantRoles().isEmpty());
		
		empty.grantRole(owner);
		assertTrue(empty.getGrantRoles().isEmpty());
		
		empty.denyRoles(roles);
		assertTrue(empty.getGrantRoles().isEmpty());
		
		empty.denyRole(owner);
		assertTrue(empty.getDenyRoles().isEmpty());
		
		DenyInterceptor inter = Mockito.mock(DenyInterceptor.class);
		
		empty.setDefaultInterceptor(inter);
		assertEquals(empty.getDefaultInterceptor(), null);
	
		empty.addInterceptor(inter);
		assertTrue(empty.getInterceptors().isEmpty());
	}
}
