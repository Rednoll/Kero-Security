package com.kero.security.core.config.action.exceptions;

public class RunnedEmptyActionException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public RunnedEmptyActionException() {
		super("Runned EMPTY action. Your Kero-Security configuration is bad, if you see this exception.");
		
	}
}
