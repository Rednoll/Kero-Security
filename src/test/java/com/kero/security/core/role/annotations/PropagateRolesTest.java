package com.kero.security.core.role.annotations;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class PropagateRolesTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
		
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertEquals(scheme.getLocalProperty("name").propagateRole(agent.getRole("OWNER")), agent.getRole("FRIEND"));
		assertEquals(scheme.getLocalProperty("name").propagateRole(agent.getRole("FRIEND")), agent.getRole("ANY"));
	}
	
	public static class TestClass {
		
		@PropagateRoles({
			@PropagateRole(from = "OWNER", to = "FRIEND"),
			@PropagateRole(from = "FRIEND", to = "ANY")
		})
		private String name;
		
		public String getName() {
			
			return this.name;
		}
	}
}
