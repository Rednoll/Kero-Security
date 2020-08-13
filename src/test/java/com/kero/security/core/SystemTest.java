package com.kero.security.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.kero.security.core.exception.AccessException;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.managers.KeroAccessManagerImpl;

public class SystemTest {

	private KeroAccessManager manager = null;
	
	@BeforeEach
	public void init() {
		
		this.manager = new KeroAccessManagerImpl();
	}
	
	@Test
	public void getProperty() {
		
		manager
			.type(TestObject.class)
				.properties("text")
					.grantFor("OWNER");
	
		TestObject obj = manager.protect(new TestObject("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultOverrideBySpecifiedRule() {
		
		manager
			.type(TestObject.class)
				.properties("text")
					.defaultGrant()
					.denyFor("OWNER");

		TestObject obj = manager.protect(new TestObject("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DeepScanSuperclass() {
		
		manager
			.type(TestObject.class)
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		manager
			.type(TestObject2.class);
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_RulesInheritance() {
		
		manager
			.type(TestObject.class)
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		manager
			.type(TestObject2.class)
				.properties("text")
					.defaultDeny()
					.grantFor("ADMIN");
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DeepScanSuperclassInterface() {
		
		manager
			.type(TestInterface.class)
				.properties("text")
					.defaultDeny()
					.grantFor("OWNER");

		manager
			.type(TestObject2.class);
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DeepScanSuperclass_RulesOverride() {
		
		manager
			.type(TestObject.class)
				.properties("text")
					.grantFor("OWNER");

		manager
			.type(TestObject2.class)
				.properties("text")
					.defaultGrant()
					.denyFor("OWNER");
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_UnsuitableRole() {
		
		manager
			.type(TestObject.class)
				.properties("text")
					.grantFor("OWNER");
	
		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
		
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultDeny_TypeLevel() {
	
		manager
			.type(TestObject.class)
				.defaultDeny();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_TypeLevel() {
		
		manager
			.type(TestObject.class)
				.defaultGrant();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultDeny_PropertyLevel() {
	
		manager
			.type(TestObject.class)
				.properties("text")
					.defaultDeny();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_PropertyLevel() {
	
		manager
			.type(TestObject.class)
				.properties("text")
					.defaultGrant();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_DefaultDeny_PropertyLevel_TypeLevel_Overriding() {
	
		manager
			.type(TestObject.class)
				.defaultGrant()
				.properties("text")
					.defaultDeny();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertThrows(AccessException.class, obj::getText);
	}
	
	@Test
	public void getProperty_DefaultGrant_PropertyLevel_TypeLevel_Overriding() {
	
		manager
			.type(TestObject.class)
				.defaultDeny()
				.properties("text")
					.defaultGrant();

		TestObject obj = manager.protect(new TestObject("test12"), "NONE");
	
		assertEquals(obj.getText(), "test12");
	}
	
	@Test
	public void getProperty_AcessibleStacking() {
	
		manager
			.type(TestObject.class)
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
	
		manager
			.type(TestObject.class)
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
		
		manager
			.type(TestObject.class)
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
	
		manager.createRole("OWNER", 10);
		manager.createRole("ADMIN", 5);
		manager.createRole("COMMON", 1);
		
		manager
			.type(TestObject.class)
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
		
		manager
			.type(TestObject.class)
				.defaultDeny()
				.property("text")
					.grantFor("OWNER")
					.failureInterceptor((obj)-> {
						
						return ((TestObject) obj).getText() + "_1";
					}, "OWNER");
		
		manager
			.type(TestObject2.class)
				.property("text")
				.denyFor("OWNER");
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertEquals(obj.getText(), "test12_1");
	}
	
	@Test
	public void getProperty_InheritDisable() {
		
		manager
			.type(TestObject.class)
				.property("text")
					.grantFor("OWNER");
		
		manager
			.type(TestObject2.class)
				.defaultDeny()
				.disableInherit();
		
		TestObject2 obj = manager.protect(new TestObject2("test12"), "OWNER");
		
		assertThrows(AccessException.class, obj::getText);
	}
}
