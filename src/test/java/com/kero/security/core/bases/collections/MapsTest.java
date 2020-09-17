package com.kero.security.core.bases.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.kero.security.core.TestObject;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.exception.AccessException;

public class MapsTest {

	private KeroAccessAgent manager = new KeroAccessAgentFactoryImpl().create();
	
	@BeforeEach
	public void init() {
		
		manager.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultGrant()
				.property("text")
					.defaultDeny()
					.addDenyInterceptor((obj)-> "forbidden", "FRIEND")
					.grantFor("OWNER");
	}
	
	@Test
	public void test_HashMap() {
	
		HashMap<String, TestObject> map = new HashMap<>();
			map.put("test object", new TestObject("test text"));
		
		test_Owner(map);
		test_None(map);
		test_Friend(map);
	}
	
	@Test
	public void test_Hashtable() {
		
		Hashtable<String, TestObject> map = new Hashtable<>();
			map.put("test object", new TestObject("test text"));
		
		test_Owner(map);
		test_None(map);
		test_Friend(map);
	}
	
	@Test
	public void test_LinkedHasMap() {
		
		LinkedHashMap<String, TestObject> map = new LinkedHashMap<>();
			map.put("test object", new TestObject("test text"));
		
		test_Owner(map);
		test_None(map);
		test_Friend(map);
	}
	
	@Test
	public void test_TreeMap() {
		
		TreeMap<String, TestObject> map = new TreeMap<>();
			map.put("test object", new TestObject("test text"));
		
		test_Owner(map);
		test_None(map);
		test_Friend(map);
	}
	
	public void test_Owner(Map<String, TestObject> set) {
		
		Map<String, TestObject> setOwner = manager.protect(set, "OWNER");
		assertEquals(setOwner.entrySet().iterator().next().getValue().getText(), "test text");
	}
	
	public void test_None(Map<String, TestObject> set) {
		
		Map<String, TestObject> setNone = manager.protect(set, "NONE");
		assertThrows(AccessException.class, ()-> setNone.entrySet().iterator().next().getValue().getText());
	}
	
	public void test_Friend(Map<String, TestObject> set) {
			
		Map<String, TestObject> setFriend = manager.protect(set, "FRIEND");
		assertEquals(setFriend.entrySet().iterator().next().getValue().getText(), "forbidden");
	}
}
