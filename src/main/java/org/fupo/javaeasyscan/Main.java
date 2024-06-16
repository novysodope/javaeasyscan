package org.fupo.javaeasyscan;

import java.io.File;

/**
 * @Describe
 * @Author novy
 * @Version 1.0
 * @CreateDate 19:42 2024/6/16
 **/
public class Main {
    public static void main(String[] args) throws Exception {
        File rootDir = new File(args[0]);
//        SQLInjectScan sqlInjectScan = new SQLInjectScan();
//        SQLInjecSplitScan sqlInjecSplitScan = new SQLInjecSplitScan();
//        CommandInjectScan commandInjectScan = new CommandInjectScan();
//        GroovyShellScan groovyShellScan = new GroovyShellScan();
//        DeserializationFastJsonScan deserializationFastJsonScan = new DeserializationFastJsonScan();

        SQLInjectScan.main(rootDir.getAbsolutePath());
        SQLInjecSplitScan.main(rootDir.getAbsolutePath());
        CommandInjectScan.main(rootDir.getAbsolutePath());
        GroovyShellScan.main(rootDir.getAbsolutePath());
        DeserializationFastJsonScan.main(rootDir.getAbsolutePath());

    }
}
