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


        String help = "Usage: java -jar javaeasyscan.jar source_code_path";
        String author = "" +
                "███████╗██╗   ██╗██████╗  ██████╗\n" +
                "██╔════╝██║   ██║██╔══██╗██╔═══██╗\n" +
                "█████╗  ██║   ██║██████╔╝██║   ██║\n" +
                "██╔══╝  ██║   ██║██╔═══╝ ██║   ██║\n" +
                "██║     ╚██████╔╝██║     ╚██████╔╝\n" +
                "╚═╝      ╚═════╝ ╚═╝      ╚═════╝\n" +
                "                       JAVAEASYSCANNER  Fupo's series\n" +
                "—————————————————————————————————————————————————————\n";
        System.out.println(author);

        if (args.length==0){
            System.out.println("Missing parameter, please enter the source code directory\n" + help);
            System.exit(0);
        }

        File rootDir = new File(args[0]);
        SQLInjectScan.main(rootDir.getAbsolutePath());
        SQLInjecSplitScan.main(rootDir.getAbsolutePath());
        CommandInjectScan.main(rootDir.getAbsolutePath());
        GroovyShellScan.main(rootDir.getAbsolutePath());
        DeserializationFastJsonScan.main(rootDir.getAbsolutePath());
    }
}
