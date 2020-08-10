package com.kero.security.core;

public class TestObject implements TestInterface {
	
	private String text;
	
	public TestObject() {
		
	}
	
	public TestObject(String text) {
		
		this.text = text;
	}
	
	public String getText() {
		
		return this.text;
	}
}
