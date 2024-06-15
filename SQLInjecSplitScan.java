package org.fupo.javaeasyscan;

import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.utils.SourceRoot;

import java.io.File;
import java.nio.file.Paths;
import java.util.*;
/**
 * @Describe
 * @Author novy
 * @Version 1.0
 * @CreateDate 15:28 2024/6/15
 **/
public class SQLInjecSplitScan {
    public static ResultUtil resultUtil = new ResultUtil();

    public static void main(String[] args) {
        File rootDir = new File(args[0]);
        scanJavaFiles(rootDir);
    }

    public static void scanJavaFiles(File dir) {
        ParserConfiguration parserConfiguration = new ParserConfiguration();
        SourceRoot sourceRoot = new SourceRoot(Paths.get(dir.getAbsolutePath()), parserConfiguration);
        List<ParseResult<CompilationUnit>> parseResults = sourceRoot.tryToParseParallelized();
        SqlInjectionVisitor visitor = new SqlInjectionVisitor();
        List<String> results = new ArrayList<>();

        for (ParseResult<CompilationUnit> parseResult : parseResults) {
            parseResult.ifSuccessful(cu -> cu.accept(visitor, results));
        }
        if (results!=null&&results.equals("")){
            resultUtil.generateHtmlReport(results, "SQL注入");
        }else {
            System.out.println("\nnot found result\n");
        }

    }

    private static class SqlInjectionVisitor extends VoidVisitorAdapter<List<String>> {
        private final Map<String, String> variableValues = new HashMap<>();
        private final Set<String> detectedInjections = new HashSet<>();
        private String currentFilePath;
        private String currentClassName;
        private String currentMethodName;

        @Override
        public void visit(ClassOrInterfaceDeclaration classOrInterface, List<String> results) {
            currentClassName = classOrInterface.getNameAsString();
            super.visit(classOrInterface, results);
        }

        @Override
        public void visit(MethodDeclaration methodDeclaration, List<String> results) {
            currentMethodName = methodDeclaration.getNameAsString();
            super.visit(methodDeclaration, results);
        }

        @Override
        public void visit(VariableDeclarator variableDeclarator, List<String> results) {
            super.visit(variableDeclarator, results);
            if (variableDeclarator.getInitializer().isPresent()) {
                Expression initializer = variableDeclarator.getInitializer().get();
                variableValues.put(variableDeclarator.getNameAsString(), initializer.toString());
            }
        }

        @Override
        public void visit(BinaryExpr binaryExpr, List<String> results) {
            super.visit(binaryExpr, results);
            if (binaryExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                if (binaryExpr.getLeft() instanceof NameExpr && binaryExpr.getRight() instanceof StringLiteralExpr) {
                    String left = binaryExpr.getLeft().toString();
                    String right = binaryExpr.getRight().asStringLiteralExpr().getValue();
                    variableValues.put(left, right);
                } else if (binaryExpr.getLeft() instanceof StringLiteralExpr && binaryExpr.getRight() instanceof NameExpr) {
                    String left = binaryExpr.getLeft().asStringLiteralExpr().getValue();
                    String right = binaryExpr.getRight().toString();
                    variableValues.put(right, left);
                }
            }
        }

        @Override
        public void visit(MethodCallExpr methodCallExpr, List<String> results) {
            super.visit(methodCallExpr, results);
            List<String> sqlMethods = Arrays.asList("update", "queryForList", "queryForMap", "execute", "query", "executeQuery", "executeUpdate", "executeBatch");
            if (sqlMethods.contains(methodCallExpr.getNameAsString())) {
                methodCallExpr.getArguments().forEach(arg -> {
                    if (arg.isNameExpr()) {
                        NameExpr nameExpr = arg.asNameExpr();
                        String variableName = nameExpr.getNameAsString();
                        if (variableValues.containsKey(variableName) && isStringConcatenation(variableValues.get(variableName))) {
                            int lineNumber = methodCallExpr.getBegin().isPresent() ? methodCallExpr.getBegin().get().line : -1;
                            String sqlStatement = variableValues.get(variableName);
                            String message = "发现" + currentClassName + "类存在SQL注入漏洞，在" + currentMethodName + "方法中，第" + lineNumber + "行：<br><pre style=\"color:red;\">" + sqlStatement + "</pre>";
                            if (detectedInjections.add(message)) {
                                results.add(message);
                            }
                        }
                    }
                });
            }
        }

        private boolean isStringConcatenation(String value) {
            return value.contains("\" + ") || value.contains(" + \"") || value.contains("\"+") || value.contains("+\"");
        }

        @Override
        public void visit(CompilationUnit compilationUnit, List<String> results) {
            currentFilePath = compilationUnit.getStorage().map(storage -> storage.getPath().toString()).orElse("Unknown");
            super.visit(compilationUnit, results);
        }
    }
}
