package com.kero.security.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.lexems.RoleLexem;
import com.kero.security.lang.tokens.RoleToken;

public class RoleLexemTest {

	@Test
	public void match() {
		
		RoleLexem lexem = new RoleLexem();
	
		assertTrue(lexem.isMatch("+OWNER"));
		assertTrue(lexem.isMatch("-COMMON"));
		
		assertFalse(lexem.isMatch("-tol-tol"));
		assertFalse(lexem.isMatch("OWNER"));
	}
	
	@Test
	public void tokenize() {
		
		RoleLexem lexem = new RoleLexem();
		
		RoleToken ownerToken = lexem.tokenize("+OWNER");
	
		assertEquals(ownerToken.getRoleName(), "OWNER");
		assertEquals(ownerToken.getAccessible(), true);
		
		RoleToken friendToken = lexem.tokenize("-FRIEND");
		
		assertEquals(friendToken.getRoleName(), "FRIEND");
		assertEquals(friendToken.getAccessible(), false);
	}
}
