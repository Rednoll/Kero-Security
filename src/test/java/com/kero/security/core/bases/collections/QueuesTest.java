package com.kero.security.core.bases.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedList;
import java.util.PriorityQueue;
import java.util.Queue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.kero.security.core.TestObject;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.exception.AccessException;

public class QueuesTest {

	private KeroAccessAgent manager = new KeroAccessAgentFactoryImpl().create();
	
	@BeforeEach
	public void init() {
		
		manager.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultGrant()
				.property("text")
					.defaultDeny()
					.addDenyInterceptor((obj, args)-> "forbidden", "FRIEND")
					.grantFor("OWNER");
	}
	
	@Test
	public void test_LinkedList() {
		
		LinkedList<TestObject> queue = new LinkedList<>();
			queue.add(new TestObject("test text"));
			
		test_Owner(queue);
		test_None(queue);
		test_Friend(queue);
	}
	
	@Test
	public void test_PriorityQueue() {
		
		PriorityQueue<TestObject> queue = new PriorityQueue<>();
			queue.add(new TestObject("test text"));
			
		test_Owner(queue);
		test_None(queue);
		test_Friend(queue);
	}
	
	public void test_Owner(Queue<TestObject> set) {
		
		Queue<TestObject> setOwner = manager.protect(set, "OWNER");
		assertEquals(setOwner.peek().getText(), "test text");
	}
	
	public void test_None(Queue<TestObject> set) {
		
		Queue<TestObject> setNone = manager.protect(set, "NONE");
		assertThrows(AccessException.class, ()-> setNone.peek().getText());
	}
	
	public void test_Friend(Queue<TestObject> set) {
			
		Queue<TestObject> setFriend = manager.protect(set, "FRIEND");
		assertEquals(setFriend.peek().getText(), "forbidden");
	}
}
