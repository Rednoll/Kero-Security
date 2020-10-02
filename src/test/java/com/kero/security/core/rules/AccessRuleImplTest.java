package com.kero.security.core.rules;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class AccessRuleImplTest {

	@Test
	public void manage() {
		
		Set<Role> roles = new HashSet<>();
			roles.add(new RoleImpl("Test"));

		Set<Role> roles2 = new HashSet<>();
			roles.add(new RoleImpl("Test Role 2"));
			
		AccessRule rule = new AccessRuleImpl(roles, true);
		assertTrue(rule.manage(roles));
		assertFalse(rule.manage(Collections.EMPTY_SET));
		assertFalse(rule.manage(roles2));
	}
	
	@Test
	public void accessible() {
		
		Set<Role> roles = new HashSet<>();
			roles.add(new RoleImpl("Test"));
	
		AccessRule rule = new AccessRuleImpl(roles, true);
		assertTrue(rule.accessible(roles));
		
		rule = new AccessRuleImpl(roles, false);
		assertFalse(rule.accessible(roles));
	}
	
	@Test
	public void getRoles() {
	
		Set<Role> roles = new HashSet<>();
			roles.add(new RoleImpl("Test"));
		
		AccessRule rule = new AccessRuleImpl(roles, true);
		
		assertTrue(rule.getRoles().equals(roles));
	}

	@Test
	public void isAllower() {
		
		AccessRule rule = new AccessRuleImpl(Collections.EMPTY_SET, true);
		assertTrue(rule.isAllower());
		
		rule = new AbsoluteAccessRule(false);
		assertFalse(rule.isAllower());
	}

	@Test
	public void isDisallower() {
		
		AccessRule rule = new AccessRuleImpl(Collections.EMPTY_SET, false);
		assertTrue(rule.isDisallower());
		
		rule = new AbsoluteAccessRule(true);
		assertFalse(rule.isDisallower());
	}
}
