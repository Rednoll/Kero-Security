package com.kero.security.core.role;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class RoleImplTest {

	@Test
	public void equalsTest() {
		
		assertTrue(new RoleImpl("OWNER").equals(new RoleImpl("OWNER")));
	}
	
	@Test
	public void compareTo() {
		
		assertTrue(new RoleImpl("A").compareTo(new RoleImpl("B")) < 0);
	}
	
	@Test
	public void getName() {
		
		assertEquals(new RoleImpl("OWNER").getName(), "OWNER");
	}
}
