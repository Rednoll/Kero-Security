package com.kero.security.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.annotations.DefaultDeny;
import com.kero.security.core.access.annotations.DefaultGrant;
import com.kero.security.core.access.annotations.GrantFor;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.exception.AccessException;
import com.kero.security.core.interceptor.DenyInterceptorBase;
import com.kero.security.core.interceptor.annotations.DenyWithInterceptor;
import com.kero.security.core.role.annotations.PropagateRole;
import com.kero.security.core.role.annotations.PropagateRoles;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class AnnotationsTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
		
		TestAnnotatedObject ownerPr = agent.protect(new TestAnnotatedObject("default_text"), "OWNER");
	
		assertEquals(ownerPr.getText(), "default_text");
		assertEquals(ownerPr.getChildren().getName(), "default_text_child");
		
		TestAnnotatedObject friendPr = agent.protect(new TestAnnotatedObject("default_text"), "FRIEND");
		
		assertEquals(friendPr.getText(), "Intercepted!");
		assertThrows(AccessException.class, friendPr.getChildren()::getName);
	}
	
	@DefaultGrant
	public static class TestAnnotatedObject {

		@DenyWithInterceptor(value = TestInterceptor.class, roles = "FRIEND")
		private String text;

		@PropagateRoles({
			@PropagateRole(from = "OWNER", to = "GUEST"),
			@PropagateRole(from = "FRIEND", to = "ANY")
		})
		private Children children;
		
		public TestAnnotatedObject() {}
		
		public TestAnnotatedObject(String text) {
			
			this.text = text;
			this.children = new Children(text+"_child");
		}
		
		public Children getChildren() {
			
			return this.children;
		}
		
		public String getText() {
			
			return this.text;
		}
	
		@DefaultDeny
		public static class Children {
			
			@GrantFor("GUEST")
			private String name;
		
			public Children() {}
			
			public Children(String name) {
				
				this.name = name;
			}
			
			public String getName() {
			
				return this.name;
			}
		}
	}
	
	public static class TestInterceptor extends DenyInterceptorBase {

		@Override
		public Object intercept(Object original, Object[] args) {
			
			return "Intercepted!";
		}
	}
}
