package org.fupo.javaeasyscan;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.type.ReferenceType;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.javaparsermodel.JavaParserFacade;
import com.github.javaparser.symbolsolver.javaparsermodel.declarations.JavaParserClassDeclaration;
import com.github.javaparser.symbolsolver.model.resolution.SymbolReference;
import com.github.javaparser.symbolsolver.model.resolution.TypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

/**
 * @Describe
 * @Author novy
 * @Version 1.0
 * @CreateDate 20:02 2024/6/14
 **/
public class ExecScanner {

    public static void main(String[] args) {
        File rootDir = new File(args[0]);
        if (!rootDir.isDirectory()) {
            System.err.println("Provided path is not a directory.");
            return;
        }

        scanJavaFiles(rootDir);
    }

    public static void scanJavaFiles(File dir) {
        List<File> javaFiles = getJavaFiles(dir);
        CombinedTypeSolver combinedTypeSolver = new CombinedTypeSolver();
        combinedTypeSolver.add(new ReflectionTypeSolver());
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedTypeSolver);
        ParserConfiguration parserConfiguration = new ParserConfiguration().setSymbolResolver(symbolSolver);
        JavaParser javaParser = new JavaParser(parserConfiguration);

        for (File javaFile : javaFiles) {
            try {
                CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                MethodCallVisitor methodCallVisitor = new MethodCallVisitor(javaFiles, javaParser);
                methodCallVisitor.visit(cu, javaFile.getAbsolutePath());
            } catch (IOException e) {
                System.err.println("Failed to parse file: " + javaFile.getAbsolutePath());
                e.printStackTrace();
            }
        }
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
        private final Map<String, String> variableDeclarations = new HashMap<>();
        private String currentMethodName = "";
        private String currentClassName = "";
        private final List<File> javaFiles;
        private final JavaParser javaParser;

        public MethodCallVisitor(List<File> javaFiles, JavaParser javaParser) {
            this.javaFiles = javaFiles;
            this.javaParser = javaParser;
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
        public void visit(VariableDeclarator variableDeclarator, String filePath) {
            super.visit(variableDeclarator, filePath);
            if (variableDeclarator.getInitializer().isPresent()) {
                Expression initializer = variableDeclarator.getInitializer().get();
                if (initializer.isMethodCallExpr()) {
                    MethodCallExpr methodCall = initializer.asMethodCallExpr();
                    if (methodCall.getNameAsString().equals("getRuntime") && methodCall.getScope().isPresent() && methodCall.getScope().get().toString().equals("Runtime")) {
                        variableDeclarations.put(variableDeclarator.getNameAsString(), "Runtime.getRuntime()");
                    }
                } else if (initializer.isObjectCreationExpr()) {
                    ObjectCreationExpr objectCreationExpr = initializer.asObjectCreationExpr();
                    if (objectCreationExpr.getType().getNameAsString().equals("ProcessBuilder")) {
                        variableDeclarations.put(variableDeclarator.getNameAsString(), "new ProcessBuilder()");
                    }
                }
            }
        }

        @Override
        public void visit(AssignExpr assignExpr, String filePath) {
            super.visit(assignExpr, filePath);
            if (assignExpr.getTarget().isNameExpr() && assignExpr.getValue().isMethodCallExpr()) {
                String variableName = assignExpr.getTarget().asNameExpr().getNameAsString();
                MethodCallExpr methodCall = assignExpr.getValue().asMethodCallExpr();
                if (methodCall.getNameAsString().equals("getRuntime") && methodCall.getScope().isPresent() && methodCall.getScope().get().toString().equals("Runtime")) {
                    variableDeclarations.put(variableName, "Runtime.getRuntime()");
                }
            } else if (assignExpr.getTarget().isNameExpr() && assignExpr.getValue().isObjectCreationExpr()) {
                String variableName = assignExpr.getTarget().asNameExpr().getNameAsString();
                ObjectCreationExpr objectCreationExpr = assignExpr.getValue().asObjectCreationExpr();
                if (objectCreationExpr.getType().getNameAsString().equals("ProcessBuilder")) {
                    variableDeclarations.put(variableName, "new ProcessBuilder()");
                }
            }
        }

        @Override
        public void visit(MethodCallExpr methodCall, String filePath) {
            if (methodCall.getNameAsString().equals("exec")) {
                int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                System.out.println(currentClassName + "类存在exec命令执行，在" + currentMethodName + "方法中，第" + lineNumber + "行");
                findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>());
            } else if (methodCall.getNameAsString().equals("start")) {
                if (isProcessBuilderStartMethod(methodCall)) {
                    int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                    System.out.println(currentClassName + "类存在ProcessBuilder命令执行，在" + currentMethodName + "方法中，第" + lineNumber + "行");
                    findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>());
                }
            }
            super.visit(methodCall, filePath);
        }

        private boolean isProcessBuilderStartMethod(MethodCallExpr methodCall) {
            try {
                return methodCall.resolve().getQualifiedSignature().contains("java.lang.ProcessBuilder.start");
            } catch (Exception e) {
                return false;
            }
        }

        private void findUsages(String className, String methodName, List<File> javaFiles, JavaParser javaParser, Set<String> visitedMethods) {
            for (File javaFile : javaFiles) {
                try {
                    CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                    new UsageVisitor(className, methodName, javaFiles, javaParser, visitedMethods).visit(cu, javaFile.getAbsolutePath());
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
            private String currentMethodName = "";
            private String currentClassName = "";

            public UsageVisitor(String className, String methodName, List<File> javaFiles, JavaParser javaParser, Set<String> visitedMethods) {
                this.className = className;
                this.methodName = methodName;
                this.javaFiles = javaFiles;
                this.javaParser = javaParser;
                this.visitedMethods = visitedMethods;
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
                        System.out.println("具体调用信息：\n" + filePath + " 第" + lineNumber + "行中 " + fileClassName + "类的" + callingMethodName + "方法调用到了 " + className + "." + methodName + "\n");
                        String calledMethod = fileClassName + "." + methodCall.getNameAsString();
                        if (!visitedMethods.contains(calledMethod)) {
                            visitedMethods.add(calledMethod);
                            findUsages(fileClassName, callingMethodName, javaFiles, javaParser, visitedMethods);
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

            private void findUsages(String className, String methodName, List<File> javaFiles, JavaParser javaParser, Set<String> visitedMethods) {
                for (File javaFile : javaFiles) {
                    try {
                        CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                        new UsageVisitor(className, methodName, javaFiles, javaParser, visitedMethods).visit(cu, javaFile.getAbsolutePath());
                    } catch (IOException e) {
                        System.err.println("Failed to parse file: " + javaFile.getAbsolutePath());
                        e.printStackTrace();
                    }
                }
            }
        }
    }
}
