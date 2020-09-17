package com.kero.security.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.exception.AccessException;

public class SystemTest {

	private KeroAccessAgent agent = null;
	
	@BeforeEach
	public void init() {
		
		this.agent = new KeroAccessAgentFactoryImpl().create();
	}
	
	@Test
	public void getProperty() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER");
	
		TestObject obj = agent.protect(new TestObject("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultOverrideBySpecifiedRule() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant()
					.denyFor("OWNER");

		TestObject obj = agent.protect(new TestObject("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DeepScanSuperclass() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		agent.getKeroAccessConfigurator()
			.scheme(TestObject2.class);
		
		TestObject2 obj = agent.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_RulesInheritance() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		agent.getKeroAccessConfigurator()
			.scheme(TestObject2.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("ADMIN");
		
		TestObject2 obj = agent.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DeepScanSuperclassInterface() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestInterface.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		agent.getKeroAccessConfigurator()
			.scheme(TestObject2.class);
		
		TestObject2 obj = agent.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DeepScanSuperclass_RulesOverride() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER");

		agent.getKeroAccessConfigurator()
			.scheme(TestObject2.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant()
					.denyFor("OWNER");
		
		TestObject2 obj = agent.protect(new TestObject2("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_UnsuitableRole() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER");
	
		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultDeny_TypeLevel() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny();

		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_TypeLevel() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultGrant();

		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultDeny_PropertyLevel() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny();

		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_PropertyLevel() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant();

		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultDeny_PropertyLevel_TypeLevel_Overriding() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultGrant()
				.properties("text")
					.defaultDeny();

		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_PropertyLevel_TypeLevel_Overriding() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant();

		TestObject obj = agent.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_AcessibleStacking() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER")
					.grantFor("ADMIN");

		TestObject obj = agent.protect(new TestObject("test12"), "OWNER");
	
		assertEquals(obj.getText(), "test12");
		
		obj = agent.protect(new TestObject("test12"), "ADMIN");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DenyInterceptor() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_OWNER";
					}, "OWNER");

		TestObject obj = agent.protect(new TestObject("test12"), "OWNER");
	
		assertEquals(obj.getText(), "test12_OWNER");
	}
	
	@Test
	public void getProperty_DenyInterceptor_CorrectChoise() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_OWNER";
					}, "OWNER")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_ADMIN";
					}, "ADMIN");

		TestObject obj = agent.protect(new TestObject("test12"), "ADMIN");
	
		assertEquals(obj.getText(), "test12_ADMIN");
	}

	@Test
	public void getProperty_DenyInterceptor_CorrectPriority() {
	
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_3";
					}, "COMMON", "OWNER", "ADMIN")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_ADMIN";
					}, "ADMIN")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_OWNER";
					}, "OWNER")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_COMMON";
					}, "COMMON")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_2";
					}, "COMMON", "ADMIN");

		TestObject obj = agent.protect(new TestObject("test12"), "ADMIN");
	
		assertEquals(obj.getText(), "test12_ADMIN");
	}
	
	@Test
	public void getProperty_InterceptorInheritance() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.grantFor("OWNER")
					.addDenyInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_1";
					}, "OWNER");
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject2.class)
				.property("text")
				.denyFor("OWNER");
		
		TestObject2 obj = agent.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12_1");
	}
	
	@Test
	public void getProperty_InheritDisable() {
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.grantFor("OWNER");
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject2.class)
				.defaultDeny()
				.disableInherit();
		
		TestObject2 obj = agent.protect(new TestObject2("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
}
