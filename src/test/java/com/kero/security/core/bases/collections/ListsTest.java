package com.kero.security.core.bases.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.kero.security.core.TestObject;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.exception.AccessException;

public class ListsTest {

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
	public void test_ArrayList() {
	
		ArrayList<TestObject> list = new ArrayList<>();
			list.add(new TestObject("test text"));
		
		test_Owner(list);
		test_None(list);
		test_Friend(list);
	}
	
	@Test
	public void test_LinkedList() {
	
		LinkedList<TestObject> list = new LinkedList<>();
			list.add(new TestObject("test text"));
		
		test_Owner(list);
		test_None(list);
		test_Friend(list);
	}
	
	@Test
	public void test_Vector() {
	
		Vector<TestObject> list = new Vector<>();
			list.add(new TestObject("test text"));
		
		test_Owner(list);
		test_None(list);
		test_Friend(list);
	}
	
	public void test_Owner(List<TestObject> set) {
		
		List<TestObject> setOwner = manager.protect(set, "OWNER");
		assertEquals(setOwner.get(0).getText(), "test text");
	}
	
	public void test_None(List<TestObject> set) {
		
		List<TestObject> setNone = manager.protect(set, "NONE");
		assertThrows(AccessException.class, ()-> setNone.get(0).getText());
	}
	
	public void test_Friend(List<TestObject> set) {
			
		List<TestObject> setFriend = manager.protect(set, "FRIEND");
		assertEquals(setFriend.get(0).getText(), "forbidden");
	}
}
