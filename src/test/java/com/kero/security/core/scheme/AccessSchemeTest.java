package com.kero.security.core.scheme;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.Access;
import com.kero.security.core.property.Property;

public class AccessSchemeTest {

	@Test
	public void verifyEmpty() {
		
		AccessScheme empty = AccessScheme.EMPTY;
		
		assertEquals(empty.collectProperties(), Collections.emptySet());
		assertEquals(empty.createLocalProperty(""), Property.EMPTY);
		assertEquals(empty.determineDefaultAccess(), Access.UNKNOWN);
		assertEquals(empty.getAgent(), null);
		assertEquals(empty.getDefaultAccess(), Access.UNKNOWN);
		assertEquals(empty.getLocalProperties(), Collections.EMPTY_SET);
		assertEquals(empty.getLocalProperty(""), Property.EMPTY);
		assertEquals(empty.getName(), null);
		assertEquals(empty.getOrCreateLocalProperty(""), Property.EMPTY);
		assertEquals(empty.getParent(), AccessScheme.EMPTY);
		assertEquals(empty.getParentProperty(""), Property.EMPTY);
		assertEquals(empty.getTypeClass(), null);
	}
	
	@Test
	public void getOrCreateLocalProperty() {
		
		AccessScheme scheme = new ClassAccessScheme();
		
		Property created = scheme.createLocalProperty("name");
		
		Property getted = scheme.getOrCreateLocalProperty("name");
	
		assertEquals(created, getted);
	}
	
	@Test
	public void addCacheWrap() {
		
		AccessScheme wrap = AccessScheme.addCacheWrap(AccessScheme.EMPTY);
		AccessScheme wrap2 = AccessScheme.addCacheWrap(wrap);
	
		assertEquals(wrap, wrap2);
	}
}
