package com.kero.security.core.lang.tokens;

public class NameToken extends KsdlTokenBase {

	private String raw;
	
	public NameToken(String raw) {
		
		this.raw = raw;
	}
	
	@Override
	public String toString() {
		return "NameToken [raw=" + raw + "]";
	}

	public String getRaw() {
		
		return this.raw;
	}
}
