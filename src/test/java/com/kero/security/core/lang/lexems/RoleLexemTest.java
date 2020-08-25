package com.kero.security.core.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class RoleLexemTest {

	@Test
	public void test() {
		
		RoleLexem lexem = new RoleLexem();
	
		assertTrue(lexem.isMatch("+OWNER"));
		assertTrue(lexem.isMatch("-COMMON"));
		
		assertFalse(lexem.isMatch("-tol-tol"));
		assertFalse(lexem.isMatch("OWNER"));
	}
}
