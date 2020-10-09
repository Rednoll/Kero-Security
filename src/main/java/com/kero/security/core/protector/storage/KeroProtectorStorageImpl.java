package com.kero.security.core.protector.storage;

import java.util.HashMap;

import com.kero.security.core.protector.BaseKeroProtector;
import com.kero.security.core.protector.KeroProtector;
import com.kero.security.core.scheme.AccessScheme;

public class KeroProtectorStorageImpl extends HashMap<AccessScheme, KeroProtector> implements KeroProtectorStorage {

	private static final long serialVersionUID = 1L;

	@Override
	public KeroProtector createProtector(AccessScheme scheme) {
	
		if(containsKey(scheme)) throw new RuntimeException("Already has protector for: "+scheme);
		
		return computeIfAbsent(scheme, BaseKeroProtector::new);
	}

	@Override
	public boolean hasProtector(AccessScheme scheme) {
		
		return containsKey(scheme);
	}

	@Override
	public KeroProtector getProtector(AccessScheme scheme) {
		
		return get(scheme);
	}
}
