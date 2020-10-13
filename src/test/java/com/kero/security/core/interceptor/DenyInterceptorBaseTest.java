package com.kero.security.core.interceptor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class DenyInterceptorBaseTest {

	@Test
	public void prepare() {
		
		Role owner = new RoleImpl("OWNER");
		Role friend = new RoleImpl("FRIEND");
		
		Set<Role> roles = new HashSet<>();
			roles.add(owner);
			
		TestInterceptor interceptor = new TestInterceptor(roles);
	
		Set<Role> sub = new HashSet<>();
			sub.add(friend);
			
		assertThrows(RuntimeException.class, ()-> {interceptor.prepare(sub);});
		
		sub.add(owner);
		
		assertDoesNotThrow(()-> {interceptor.prepare(sub);});
	
		assertThrows(RuntimeException.class, ()-> {interceptor.prepare(Collections.emptySet());});
	}
	
	public static class TestInterceptor extends DenyInterceptorBase {

		public TestInterceptor(Set<Role> roles) {
			super(null, roles);
		}
		
		@Override
		public Object intercept(Object original, Object[] args) {
		
			return null;
		}
	}
}
