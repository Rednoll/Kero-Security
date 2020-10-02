package com.kero.security.core.rules;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Test;

public class AbsoluteAccessRuleTest {
	
	@Test
	public void manage() {
		
		AccessRule rule = new AbsoluteAccessRule(true);
		assertFalse(rule.manage(Collections.EMPTY_SET));
	}
	
	@Test
	public void accessible() {
		
		AccessRule rule = new AbsoluteAccessRule(true);
		assertTrue(rule.accessible(Collections.EMPTY_SET));
	
		rule = new AbsoluteAccessRule(false);
		assertFalse(rule.accessible(Collections.EMPTY_SET));
	}

	@Test
	public void getRoles() {
	
		AccessRule rule = new AbsoluteAccessRule(true);
		
		assertTrue(rule.getRoles().isEmpty());
	}

	@Test
	public void isAllower() {
		
		AccessRule rule = new AbsoluteAccessRule(true);
		assertTrue(rule.isAllower());
		
		rule = new AbsoluteAccessRule(false);
		assertFalse(rule.isAllower());
	}

	@Test
	public void isDisallower() {
		
		AccessRule rule = new AbsoluteAccessRule(false);
		assertTrue(rule.isDisallower());
		
		rule = new AbsoluteAccessRule(true);
		assertFalse(rule.isDisallower());
	}
}
