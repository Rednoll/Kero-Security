package com.kero.security.core.scheme.strategy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class DefaultAccessSchemeNamingStrategyTest {

	@Test
	public void getName() {
		
		DefaultAccessSchemeNamingStrategy strategy = new DefaultAccessSchemeNamingStrategy();
	
		assertEquals(strategy.getName(DefaultAccessSchemeNamingStrategy.class), "DefaultAccessSchemeNamingStrategy");
	}
}
