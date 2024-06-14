package org.fupo.javaeasyscan;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @Describe
 * @Author novy
 * @Version 1.0
 * @CreateDate 20:02 2024/6/14
 **/
public class CommandInjectScan {

    public static void main(String[] args) {
        File rootDir = new File(args[0]);
        List<String> results = scanJavaFiles(rootDir);
        if (!results.isEmpty()) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd_HHmmss");
            String timestamp = sdf.format(new Date());
            generateHtmlReport(results, "exec_scan_report_" + timestamp + ".html");
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
        private final Map<String, String> variableDeclarations = new HashMap<>();
        private String currentMethodName = "";
        private String currentClassName = "";
        private final List<File> javaFiles;
        private final JavaParser javaParser;
        private final List<String> results;

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
                StringBuilder result = new StringBuilder();
                result.append(currentClassName).append("类存在exec命令执行，在").append(currentMethodName).append("方法中，第").append(lineNumber).append("行:\n");
                result.append("<pre style=\"color:red;\">" + getLineContent(filePath, lineNumber)).append("</pre>\n");
                findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>(), result);
                results.add(result.toString());
            } else if (methodCall.getNameAsString().equals("start")) {
                if (isProcessBuilderStartMethod(methodCall)) {
                    int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                    StringBuilder result = new StringBuilder();
                    result.append(currentClassName).append("类存在ProcessBuilder命令执行，在").append(currentMethodName).append("方法中，第").append(lineNumber).append("行:\n");
                    result.append("<pre style=\"color:red;\">" + getLineContent(filePath, lineNumber)).append("</pre>\n");
                    findUsages(currentClassName, currentMethodName, javaFiles, javaParser, new HashSet<>(), result);
                    results.add(result.toString());
                }
            }
            super.visit(methodCall, filePath);
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
                return methodCall.resolve().getQualifiedSignature().contains("java.lang.ProcessBuilder.start");
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

    public static void generateHtmlReport(List<String> results, String filePath) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filePath))) {
            writer.println("<html>");
            writer.println("<head>");
            writer.println("<title>Fupo JavaEasyScan Result</title>");
            writer.println("<style>");
            writer.println("body { font-family: Arial, sans-serif; margin: 40px; }");
            writer.println("h1 { text-align: center; color: #333; }");
            writer.println(".container { margin-bottom: 20px; }");
            writer.println(".title { font-size: 18px; font-weight: bold; cursor: pointer; padding: 10px; background: #eee; border: 1px solid #ddd; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }");
            writer.println(".content { display: none; padding: 10px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 4px 4px; }");
            writer.println(".content p { margin: 0; white-space: pre-wrap; }");
            writer.println(".arrow { font-size: 12px; margin-left: 10px; }");
            writer.println("</style>");
            writer.println("</head>");
            writer.println("<body>");
            writer.println("<h1>Fupo JavaEasyScan CodeAudit Report</h1>");
            for (int i = 0; i < results.size(); i++) {
                writer.println("<div class='container'>");
                writer.printf("<div class='title'>命令执行 %d <span class='arrow'>&#9654;</span></div>%n", i + 1);
                writer.println("<div class='content'>");
                writer.printf("<p>%s</p>%n", results.get(i).replace("\n", "<br>"));
                writer.println("</div>");
                writer.println("</div>");
            }
            writer.println("<script>");
            writer.println("document.querySelectorAll('.title').forEach(title => {");
            writer.println("    title.addEventListener('click', () => {");
            writer.println("        const content = title.nextElementSibling;");
            writer.println("        const arrow = title.querySelector('.arrow');");
            writer.println("        if (content.style.display === 'block') {");
            writer.println("            content.style.display = 'none';");
            writer.println("            arrow.innerHTML = '&#9654;';");
            writer.println("        } else {");
            writer.println("            content.style.display = 'block';");
            writer.println("            arrow.innerHTML = '&#9660;';");
            writer.println("        }");
            writer.println("    });");
            writer.println("});");
            writer.println("</script>");
            writer.println("</body>");
            writer.println("</html>");
            System.out.println("Created report: " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
