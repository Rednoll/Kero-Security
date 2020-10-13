package com.kero.security.lang.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.nodes.KsdlRootNode;

public class RootNodeListTest {

	@Test
	public void getAllOf() {
		
		RootNodeList list = new RootNodeList();
			list.add(new TestRootNode1());
			list.add(new TestRootNode2());
			list.add(new TestRootNode1());
		
		assertEquals(list.getAllOf(TestRootNode1.class).size(), 2);
		assertEquals(list.getAllOf(TestRootNode2.class).size(), 1);
	}
	
	public static class TestRootNode1 implements KsdlRootNode {}
	public static class TestRootNode2 implements KsdlRootNode {}
}
