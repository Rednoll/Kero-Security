package com.kero.security.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.managers.KeroAccessManagerImpl;
import com.kero.security.core.scheme.AccessProxy;

public class CustomProxyTest {

	@Test
	public void customProxy() {
		
		KeroAccessManager manager = new KeroAccessManagerImpl();
		
		manager
			.scheme(TestObject.class)
				.defaultDeny()
				.proxy(TestObjectProxy.class)
				.property("text")
					.grantFor("OWNER");
		
		TestObject obj = manager.protect(new TestObject("test text!"), "OWNER");
	
		assertEquals(obj.getText(), "test text!");
	}
	
	public static class TestObjectProxy extends TestObject implements AccessProxy {

		private TestObject original;
		private PreparedAccessConfiguration pac;
		
		public TestObjectProxy(TestObject original, PreparedAccessConfiguration pac) {
			
			this.original = original;
			this.pac = pac;
		}

		@Override
		public String getText() {
			
			return this.original.getText();
		}

		@Override
		public int compareTo(TestObject o) {
			
			return this.original.compareTo(o);
		}
		
		@Override
		public Object getOriginal() {
			
			return this.original;
		}

		@Override
		public PreparedAccessConfiguration getConfiguration() {
			
			return this.pac;
		}	
	}
}
