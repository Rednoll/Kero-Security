package com.kero.security.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.kero.security.core.exception.AccessException;

public class SystemTest {

	private KeroAccessManager manager = null;
	
	@BeforeEach
	public void init() {
		
		this.manager = new KeroAccessManagerImpl();
	}
	
	@Test
	public void getProperty() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER");
	
		TestObject obj = manager.protect(new TestObject("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultOverrideBySpecifiedRule() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant()
					.denyFor("OWNER");

		TestObject obj = manager.protect(new TestObject("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DeepScanSuperclass() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		manager.getConfigurator()
			.scheme(TestObject2.class);
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_RulesInheritance() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		manager.getConfigurator()
			.scheme(TestObject2.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("ADMIN");
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DeepScanSuperclassInterface() {
		
		manager.getConfigurator()
			.scheme(TestInterface.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		manager.getConfigurator()
			.scheme(TestObject2.class);
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DeepScanSuperclass_RulesOverride() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER");

		manager.getConfigurator()
			.scheme(TestObject2.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant()
					.denyFor("OWNER");
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_UnsuitableRole() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER");
	
		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultDeny_TypeLevel() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_TypeLevel() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultGrant();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultDeny_PropertyLevel() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultDeny();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_PropertyLevel() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultDeny_PropertyLevel_TypeLevel_Overriding() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultGrant()
				.properties("text")
					.defaultDeny();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_PropertyLevel_TypeLevel_Overriding() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_AcessibleStacking() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.properties("text")
					.grantFor("OWNER")
					.grantFor("ADMIN");

		TestObject obj = manager.protect(new TestObject("test12"), "OWNER");
	
		assertEquals(obj.getText(), "test12");
		
		obj = manager.protect(new TestObject("test12"), "ADMIN");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DenyInterceptor() {
	
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_OWNER";
					}, "OWNER");

		TestObject obj = manager.protect(new TestObject("test12"), "OWNER");
	
		assertEquals(obj.getText(), "test12_OWNER");
	}
	
	@Test
	public void getProperty_DenyInterceptor_CorrectChoise() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_OWNER";
					}, "OWNER")
					.denyWithInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_ADMIN";
					}, "ADMIN");

		TestObject obj = manager.protect(new TestObject("test12"), "ADMIN");
	
		assertEquals(obj.getText(), "test12_ADMIN");
	}

	@Test
	public void getProperty_DenyInterceptor_CorrectPriority() {
	
		manager.getConfigurator()
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

		TestObject obj = manager.protect(new TestObject("test12"), "ADMIN");
	
		assertEquals(obj.getText(), "test12_ADMIN");
	}
	
	@Test
	public void getProperty_InterceptorInheritance() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.grantFor("OWNER")
					.addDenyInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_1";
					}, "OWNER");
		
		manager.getConfigurator()
			.scheme(TestObject2.class)
				.property("text")
				.denyFor("OWNER");
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12_1");
	}
	
	@Test
	public void getProperty_InheritDisable() {
		
		manager.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.grantFor("OWNER");
		
		manager.getConfigurator()
			.scheme(TestObject2.class)
				.defaultDeny()
				.disableInherit();
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
}
