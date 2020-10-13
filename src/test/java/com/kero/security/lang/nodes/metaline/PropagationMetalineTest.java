package com.kero.security.lang.nodes.metaline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.property.Property;
import com.kero.security.core.scheme.AccessScheme;

public class PropagationMetalineTest {

	@Test
	public void interpret() {
		
		Map<String, String> map = new HashMap<>();
			map.put("OWNER", "FRIEND");
		
		PropagationMetaline metaline = new PropagationMetaline(map);
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
		Property prop = scheme.getOrCreateLocalProperty("text");
		
		metaline.interpret(agent, prop);
	
		assertEquals(prop.propagateRole(agent.getRole("OWNER")), agent.getRole("FRIEND"));
	}
	
	public static class TestClass {}
}
