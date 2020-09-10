package com.kero.security.lang.provider.resource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileResource implements KsdlTextResource {

	private String[] suffixes;
	private File file;
	
	public FileResource(File file) {
		
		this.file = file;
		this.suffixes = new String[] {".ks", ".k-s"};
	}
	
	public FileResource(File file, String... suffixes) {
		this(file);
		
		this.suffixes = suffixes;
	}
	
	@Override
	public String getRawText() {
		
		System.out.println("Call getRawText");
		
		StringBuilder builder = new StringBuilder();
		 
		collectText(this.file, builder);
		
		return builder.toString();
	}
	
	private void collectText(File src, StringBuilder builder) {
		
		if(src.isFile()) {
			
			if(isSuitable(src)) {
				
				try {
					
					builder.append(new String(Files.readAllBytes(src.toPath())));
				}
				catch(IOException e) {
					
					throw new RuntimeException(e);
				}
			}
		}
		else if(src.isDirectory()) {
			
			for(File sub : src.listFiles()) {
				
				collectText(sub, builder);
			}
		}
	}
	
	private boolean isSuitable(File file) {
		
		for(String suffix : suffixes) {
		
			if(file.getName().endsWith(suffix)) {
				
				return true;
			}
		}
		
		return false;
	}
}
