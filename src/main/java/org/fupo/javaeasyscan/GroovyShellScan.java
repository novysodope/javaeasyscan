package org.fupo.javaeasyscan;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
/**
 * @Describe Groovy代码执行检测模块
 * @Author novy
 * @Version 1.0
 * @CreateDate 16:56 2024/6/16
 **/
public class GroovyShellScan {
    public static ResultUtil resultUtil;
    public static String topic = "Groovy代码执行";
    private static final Logger logger = LoggerFactory.getLogger(CommandInjectScan.class);

    public static void main(String args) {
        File rootDir = new File(args);
        List<String> results = scanJavaFiles(rootDir);
        if (!results.isEmpty()) {
            resultUtil.generateHtmlReport(results, topic);
        } else {
            System.out.println("\nnot found result\n");
        }
    }

    public static List<String> scanJavaFiles(File dir) {
        List<File> javaFiles = getJavaFiles(dir);
        List<String> results = new ArrayList<>();
        CombinedTypeSolver combinedTypeSolver = new CombinedTypeSolver();
        combinedTypeSolver.add(new ReflectionTypeSolver());
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedTypeSolver);
        ParserConfiguration parserConfiguration = new ParserConfiguration().setSymbolResolver(symbolSolver);
        JavaParser javaParser = new JavaParser(parserConfiguration);

        for (File javaFile : javaFiles) {
            logger.info("scan file: " + javaFile.getName());
            try {
                CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                MethodCallVisitor methodCallVisitor = new MethodCallVisitor(javaFiles, javaParser, results);
                methodCallVisitor.visit(cu, javaFile.getAbsolutePath());
            } catch (IOException e) {
                System.err.println("Failed to parse file: " + javaFile.getAbsolutePath());
                e.printStackTrace();
            }
        }
        return results;
    }

    public static List<File> getJavaFiles(File dir) {
        List<File> javaFiles = new ArrayList<>();
        if (dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                if (file.isDirectory()) {
                    javaFiles.addAll(getJavaFiles(file));
                } else if (file.getName().endsWith(".java")) {
                    javaFiles.add(file);
                }
            }
        }
        return javaFiles;
    }

    private static class MethodCallVisitor extends VoidVisitorAdapter<String> {
        private final Map<String, String> variableTypes = new HashMap<>();
        private final Map<String, String> variableDeclarations = new HashMap<>();
        private String currentMethodName = "";
        private String currentClassName = "";
        private final List<File> javaFiles;
        private final JavaParser javaParser;
        private final List<String> results;
        private String currentFilePath;

        public MethodCallVisitor(List<File> javaFiles, JavaParser javaParser, List<String> results) {
            this.javaFiles = javaFiles;
            this.javaParser = javaParser;
            this.results = results;
        }

        @Override
        public void visit(ClassOrInterfaceDeclaration classOrInterface, String filePath) {
            currentClassName = classOrInterface.getNameAsString();
            super.visit(classOrInterface, filePath);
        }

        @Override
        public void visit(MethodDeclaration methodDeclaration, String filePath) {
            currentMethodName = methodDeclaration.getNameAsString();
            super.visit(methodDeclaration, filePath);
        }

        @Override
        public void visit(MethodCallExpr methodCall, String filePath) {
            super.visit(methodCall, filePath);
            if (methodCall.getNameAsString().equals("parse")) {
                methodCall.getScope().ifPresent(scope -> {
                    if (scope.isNameExpr()) {
                        String scopeName = scope.asNameExpr().getNameAsString();
                        if (variableTypes.containsKey(scopeName) && variableTypes.get(scopeName).equals("GroovyShell")) {
                            int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                            StringBuilder result = new StringBuilder();
                            result.append(currentClassName).append("类存在groovy代码执行，在").append(currentMethodName).append("方法中，第").append(lineNumber).append("行:\n");
                            result.append("<pre style=\"color:red;\">" + getLineContent(filePath, lineNumber)).append("</pre>\n");
                            findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>(), result);
                            results.add(result.toString());
                        }
                    }
                });
            }else if (methodCall.getNameAsString().equals("evaluate")) {
                if (isProcessBuilderStartMethod(methodCall)) {
                    int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                    StringBuilder result = new StringBuilder();
                    methodCall.getScope().ifPresent(scope -> {
                        logger.info("method call scope: " + scope );
                    });
                    result.append(currentClassName).append("类存在groovy代码执行，在").append(currentMethodName).append("方法中，第").append(lineNumber).append("行:\n");
                    result.append("<pre style=\"color:red;\">" + getLineContent(filePath, lineNumber)).append("</pre>\n");
                    findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>(), result);
                    results.add(result.toString());
                }
            }
        }


        @Override
        public void visit(VariableDeclarator variableDeclarator, String filePath) {

            if (variableDeclarator.getType().asString().equals("GroovyShell")) {
                variableTypes.put(variableDeclarator.getNameAsString(), "GroovyShell");
            }
            super.visit(variableDeclarator, filePath);
        }

        @Override
        public void visit(ObjectCreationExpr objectCreationExpr, String filePath) {

            if (objectCreationExpr.getType().asString().equals("GroovyShell")) {
                objectCreationExpr.getParentNode().ifPresent(parent -> {
                    if (parent instanceof MethodCallExpr) {
                        MethodCallExpr methodCallExpr = (MethodCallExpr) parent;
                        if (methodCallExpr.getNameAsString().equals("parse")) {
                            int lineNumber = methodCallExpr.getBegin().isPresent() ? methodCallExpr.getBegin().get().line : -1;
                            StringBuilder result = new StringBuilder();
                            result.append("发现").append(currentClassName).append("类存在Groovy代码执行，在").append(currentMethodName).append("方法中，第").append(lineNumber).append("行：<br><pre style=\"color:red;\">").append(methodCallExpr).append("</pre>");
                            findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>(), result);
                            results.add(result.toString());
                        }
                    }
                });
            }
            super.visit(objectCreationExpr, filePath);
        }



        private String getLineContent(String filePath, int lineNumber) {
            if (lineNumber > 0) {
                try {
                    List<String> lines = Files.readAllLines(new File(filePath).toPath());
                    if (lineNumber <= lines.size()) {
                        return lines.get(lineNumber - 1).trim();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return "";
        }

        private boolean isProcessBuilderStartMethod(MethodCallExpr methodCall) {
            try {
                return methodCall.toString().contains("GroovyShell().parse") || methodCall.toString().contains("GroovyShell().evaluate");
            } catch (Exception e) {
                return false;
            }
        }

        private void findUsages(String className, String methodName, List<File> javaFiles, JavaParser javaParser, Set<String> visitedMethods, StringBuilder result) {
            for (File javaFile : javaFiles) {
                try {
                    CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                    new UsageVisitor(className, methodName, javaFiles, javaParser, visitedMethods, result).visit(cu, javaFile.getAbsolutePath());
                } catch (IOException e) {
                    System.err.println("Failed to parse file: " + javaFile.getAbsolutePath());
                    e.printStackTrace();
                }
            }
        }

        private static class UsageVisitor extends VoidVisitorAdapter<String> {
            private final String className;
            private final String methodName;
            private final List<File> javaFiles;
            private final JavaParser javaParser;
            private final Set<String> visitedMethods;
            private final StringBuilder result;
            private String currentMethodName = "";
            private String currentClassName = "";

            public UsageVisitor(String className, String methodName, List<File> javaFiles, JavaParser javaParser, Set<String> visitedMethods, StringBuilder result) {
                this.className = className;
                this.methodName = methodName;
                this.javaFiles = javaFiles;
                this.javaParser = javaParser;
                this.visitedMethods = visitedMethods;
                this.result = result;
            }

            @Override
            public void visit(ClassOrInterfaceDeclaration classOrInterface, String filePath) {
                currentClassName = classOrInterface.getNameAsString();
                super.visit(classOrInterface, filePath);
                String fileClassName = classOrInterface.getNameAsString();
                classOrInterface.findAll(MethodCallExpr.class).forEach(methodCall -> {
                    if (methodCall.getScope().isPresent() && methodCall.getScope().get().toString().toLowerCase().contains(className.toLowerCase()) && methodCall.getNameAsString().contains(methodName)) {
                        int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                        String callingMethodName = getContainingMethodName(methodCall);
                        result.append("<b>往上继续跟进发现具体调用信息：</b>\n").append(filePath).append(" 第").append(lineNumber).append("行中 ").append(fileClassName).append("类的").append(callingMethodName).append("方法调用到了 ").append(className).append("的").append(methodName).append("方法：\n");
                        result.append("<pre style=\"color:red;\">" + getLineContent(filePath, lineNumber)).append("</pre>\n");
                        String methodKey = fileClassName + "." + callingMethodName;
                        if (!visitedMethods.contains(methodKey)) {
                            visitedMethods.add(methodKey);
                            findUsages(fileClassName, callingMethodName, javaFiles, javaParser, visitedMethods, result);
                        }
                    }
                });
            }

            @Override
            public void visit(MethodDeclaration methodDeclaration, String filePath) {
                currentMethodName = methodDeclaration.getNameAsString();
                super.visit(methodDeclaration, filePath);
            }

            private String getContainingMethodName(MethodCallExpr methodCall) {
                return methodCall.findAncestor(MethodDeclaration.class)
                        .map(MethodDeclaration::getNameAsString)
                        .orElse("Unknown Method");
            }

            private void findUsages(String className, String methodName, List<File> javaFiles, JavaParser javaParser, Set<String> visitedMethods, StringBuilder result) {
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                        new UsageVisitor(className, methodName, javaFiles, javaParser, visitedMethods, result).visit(cu, javaFile.getAbsolutePath());
                    } catch (IOException e) {
                        System.err.println("Failed to parse file: " + javaFile.getAbsolutePath());
                        e.printStackTrace();
                    }
                }
            }

            private String getLineContent(String filePath, int lineNumber) {
                if (lineNumber > 0) {
                    try {
                        List<String> lines = Files.readAllLines(new File(filePath).toPath());
                        if (lineNumber <= lines.size()) {
                            return lines.get(lineNumber - 1).trim();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return "";
            }
        }
    }
}

