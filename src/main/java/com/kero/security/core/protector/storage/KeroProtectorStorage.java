package com.kero.security.core.protector.storage;

import com.kero.security.core.protector.KeroProtector;
import com.kero.security.core.scheme.AccessScheme;

public interface KeroProtectorStorage {

	public default KeroProtector getOrCreateProtector(AccessScheme scheme) {
		
		return hasProtector(scheme) ? getProtector(scheme) : createProtector(scheme);
	}

	public KeroProtector createProtector(AccessScheme scheme);
	public boolean hasProtector(AccessScheme scheme);
	public KeroProtector getProtector(AccessScheme scheme);
	
	public static KeroProtectorStorage create() {
		
		return new KeroProtectorStorageImpl();
	}
}