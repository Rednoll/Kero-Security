package com.kero.security.core;

public class TestObject implements Comparable<TestObject> {
	
	private String text;
	
	public TestObject() {
		
	}
	
	public TestObject(String text) {
		
		this.text = text;
	}
	
	public String getText() {
		
		return this.text;
	}

	@Override
	public int compareTo(TestObject o) {
		
		return this.text.compareTo(o.text);
	}
}
